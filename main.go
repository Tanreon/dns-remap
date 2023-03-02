package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jinzhu/configor"

	log "github.com/sirupsen/logrus"
	defLog "log"
)

var (
	ctx = context.Background()

	workingDir string
	config     Config
	interrupt  IInterrupt
)

func initConfig(configFilePath string) {
	if err := configor.Load(&config, configFilePath); err != nil {
		defLog.Fatalf("[%s] failed to init config: %v", "configor.Load", err)
	}
}

func initInterrupt() {
	interrupt = NewInterrupt()
}

func initLogger(logLevel string) {
	defLog.SetOutput(io.Discard) // mute default logger

	// init advanced logger
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		defLog.Fatalf("[%s] log level parse error: %v", "log.ParseLevel", err)
	}

	log.SetLevel(level)

	//

	location, _ := time.LoadLocation("UTC")

	log.SetOutput(os.Stdout)
	log.SetFormatter(&LogFormatter{
		TimeZoneLocation: location,
		TimestampFormat:  "02.01.06 03:04:05.000",
		LogFormat:        "[%time%][%slvl%] %msg%\n",
	})
}

func main() {
	var err error
	workingDir, err = os.Getwd()
	if err != nil {
		log.Fatalf("[%s] failed to get working dir: %v", "os.Getwd", err)
	}

	//

	initInterrupt()

	if len(os.Args) > 1 {
		initConfig(os.Args[1])
	} else {
		initConfig(filepath.Join(workingDir, "config", "config.json"))
	}

	initLogger(config.LogLevel)

	//

	log.Printf("starting DNS server")

	_, err = NewServer(config.Server, config.Subnet)
	if err != nil {
		panic(err)
	}

	for range time.Tick(time.Millisecond * 10) {
		if interrupt.IsInterrupted() {
			break
		}
	}
}
