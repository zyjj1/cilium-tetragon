// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/metrics/mapmetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/proc"
	lru "github.com/hashicorp/golang-lru/v2"
)

type Cache struct {
	cache      *lru.Cache[string, *ProcessInternal]
	deleteChan chan *ProcessInternal
	stopChan   chan bool
}

// garbage collection states
const (
	inUse = iota
	deletePending
	deleteReady
	deleted
)

// garbage collection run interval
const (
	intervalGC = time.Second * 30
)

func (pc *Cache) cacheGarbageCollector() {
	ticker := time.NewTicker(intervalGC)
	pc.deleteChan = make(chan *ProcessInternal)
	pc.stopChan = make(chan bool)

	go func() {
		var deleteQueue, newQueue []*ProcessInternal

		for {
			select {
			case <-pc.stopChan:
				ticker.Stop()
				pc.cache.Purge()
			case <-ticker.C:
				newQueue = newQueue[:0]
				for _, p := range deleteQueue {
					/* If the ref != 0 this means we have bounced
					 * through !refcnt and now have a refcnt. This
					 * can happen if we receive the following,
					 *
					 *     execve->close->connect
					 *
					 * where the connect/close sequence is received
					 * OOO. So bounce the process from the remove list
					 * and continue. If the refcnt hits zero while we
					 * are here the channel will serialize it and we
					 * will handle normally. There is some risk that
					 * we skip 2 color bands if it just hit zero and
					 * then we run ticker event before the delete
					 * channel. We could use a bit of color to avoid
					 * later if we care. Also we may try to delete the
					 * process a second time, but that is harmless.
					 */
					ref := atomic.LoadUint32(&p.refcnt)
					if ref != 0 {
						continue
					}
					if p.color == deleteReady {
						p.color = deleted
						pc.remove(p.process)
					} else {
						newQueue = append(newQueue, p)
						p.color = deleteReady
					}
				}
				deleteQueue = newQueue
			case p := <-pc.deleteChan:
				// duplicate deletes can happen, if they do reset
				// color to pending and move along. This will cause
				// the GC to keep it alive for at least another pass.
				// Notice color is only ever touched inside GC behind
				// select channel logic so should be safe to work on
				// and assume its visible everywhere.
				if p.color != inUse {
					p.color = deletePending
					continue
				}
				// The object has already been deleted let if fall of
				// the edge of the world. Hitting this could mean our
				// GC logic deleted a process too early.
				// TBD add a counter around this to alert on it.
				if p.color == deleted {
					continue
				}
				p.color = deletePending
				deleteQueue = append(deleteQueue, p)
			}
		}
	}()
}

func (pc *Cache) deletePending(process *ProcessInternal) {
	pc.deleteChan <- process
}

func (pc *Cache) refDec(p *ProcessInternal) {
	ref := atomic.AddUint32(&p.refcnt, ^uint32(0))
	if ref == 0 {
		pc.deletePending(p)
	}
}

func (pc *Cache) refInc(p *ProcessInternal) {
	atomic.AddUint32(&p.refcnt, 1)
}

func (pc *Cache) Purge() {
	pc.stopChan <- true
}

func NewCache(
	processCacheSize int,
) (*Cache, error) {
	lruCache, err := lru.NewWithEvict(
		processCacheSize,
		func(_ string, _ *ProcessInternal) {
			mapmetrics.MapDropInc("processLru")
		},
	)
	if err != nil {
		return nil, err
	}
	pm := &Cache{
		cache: lruCache,
	}
	update := func() {
		mapmetrics.MapSizeSet("processLru", processCacheSize, float64(pm.cache.Len()))
	}
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		for {
			<-ticker.C
			update()
			func() {
				numErrors := 0
				allPIDs := printAllPidsNs(option.Config.ProcFS)
				for i, k := range pm.cache.Keys() {
					if pi, err := pm.get(k); err == nil {
						if _, ok := allPIDs[procTuple{
							pid:   int(pi.process.Pid.Value),
							ktime: pi.ktime,
						}]; !ok {
							if pi.refcnt != 0 && pi.process.Pid.Value != 0 {
								logger.GetLogger().Warnf("[%d] key: %s, pid: %d, ktime: %d, binary: %s, refcnt: %d", i, k, pi.process.Pid.Value, pi.ktime, pi.process.Binary, pi.refcnt)
								numErrors += 1
							}
						}
					}
				}
				if numErrors == 0 {
					logger.GetLogger().Warnf("processLRU check is successful with cache size %d", pm.cache.Len())
				} else {
					logger.GetLogger().Warnf("processLRU check completed with %d errors and cache size %d", numErrors, pm.cache.Len())
				}
				mapmetrics.SetLRUErrors(float64(numErrors))
			}()
		}
	}()
	pm.cacheGarbageCollector()
	return pm, nil
}

type procTuple struct {
	pid   int
	ktime uint64
}

func printAllPIDsFor(procPath string, pid int, ktime uint64) []procTuple {
	retArray := make([]procTuple, 0)

	// sfile := "/proc/" + strconv.Itoa(pid) + "/status"
	sfile := filepath.Join(procPath, strconv.Itoa(pid), "status")

	file, err := os.Open(sfile)
	if err != nil {
		// Probably, the process terminated between the time we
		// accessed the namespace files and the time we tried to
		// open /proc/PID/status.
		fmt.Print("[can't open " + sfile + "]")
		return retArray
	}

	defer file.Close() // Close file on return from this function.

	re := regexp.MustCompile(":[ \t]*")

	// Scan file line by line, looking for 'NStgid:' entry, and print
	// corresponding set of PIDs.

	s := bufio.NewScanner(file)
	for s.Scan() {
		match, _ := regexp.MatchString("^NStgid:", s.Text())
		if match {
			tokens := re.Split(s.Text(), -1)
			pids := strings.Fields(tokens[1])
			for _, p := range pids {
				// fmt.Printf("[ %s %d ]\n", p, ktime)
				intPid, _ := strconv.Atoi(p)
				retArray = append(retArray, procTuple{
					pid:   intPid,
					ktime: ktime,
				})
			}
			break
		}
	}

	return retArray
}

func printAllPidsNs(procPath string) map[procTuple]struct{} {
	allPIDs := make(map[procTuple]struct{})

	procFS, err := os.ReadDir(procPath)
	if err != nil {
		return allPIDs
	}

	for _, d := range procFS {
		if !d.IsDir() {
			continue
		}

		pathName := filepath.Join(procPath, d.Name())

		_, err := os.ReadFile(filepath.Join(pathName, "cmdline"))
		if err != nil {
			continue
		}
		// if string(cmdline) == "" {
		// 	continue
		// }

		procPid, err := proc.GetProcPid(d.Name())
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("pid read error")
			continue
		}

		stats, err := proc.GetProcStatStrings(pathName)
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("stats read error")
			continue
		}

		ktime, err := proc.GetStatsKtime(stats)
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("ktime read error")
		}

		realPid, _ := strconv.ParseInt(d.Name(), 10, 0)

		if int64(procPid) != realPid {
			logger.GetLogger().WithError(err).Warnf("procPid[%d] != readPid[%d]", procPid, realPid)
		}

		pidArr := printAllPIDsFor(procPath, int(realPid), ktime)
		for _, p := range pidArr {
			// logger.GetLogger().Warnf("===>[%d %d]", p.pid, p.ktime)
			allPIDs[p] = struct{}{}
		}
	}

	return allPIDs
}

func (pc *Cache) get(processID string) (*ProcessInternal, error) {
	process, ok := pc.cache.Get(processID)
	if !ok {
		logger.GetLogger().WithField("id in event", processID).Debug("process not found in cache")
		errormetrics.ErrorTotalInc(errormetrics.ProcessCacheMissOnGet)
		return nil, fmt.Errorf("invalid entry for process ID: %s", processID)
	}
	return process, nil
}

// Add a ProcessInternal structure to the cache. Must be called only from
// clone or execve events
func (pc *Cache) add(process *ProcessInternal) bool {
	evicted := pc.cache.Add(process.process.ExecId, process)
	if evicted {
		errormetrics.ErrorTotalInc(errormetrics.ProcessCacheEvicted)
	}
	return evicted
}

func (pc *Cache) remove(process *tetragon.Process) bool {
	present := pc.cache.Remove(process.ExecId)
	if !present {
		errormetrics.ErrorTotalInc(errormetrics.ProcessCacheMissOnRemove)
	}
	return present
}

func (pc *Cache) len() int {
	return pc.cache.Len()
}
