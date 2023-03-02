package main

import (
	"os"
	"os/signal"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
)

type IInterrupt interface {
	IsInterrupted() bool
	Interrupt()
}

type Interrupt struct {
	mutex         *sync.Mutex
	isInterrupted bool
}

func (i *Interrupt) IsInterrupted() bool {
	defer i.mutex.Unlock()
	i.mutex.Lock()

	return i.isInterrupted
}

func (i *Interrupt) Interrupt() {
	defer i.mutex.Unlock()
	i.mutex.Lock()

	i.isInterrupted = true
}

func NewInterrupt() IInterrupt {
	signalChan := make(chan os.Signal)
	signal.Notify(signalChan, syscall.SIGTERM)
	interrupt := Interrupt{mutex: &sync.Mutex{}}

	go func() {
		<-signalChan
		log.Info("received terminate signal, waiting for threads stop...")
		interrupt.Interrupt()
	}()

	return &interrupt
}
