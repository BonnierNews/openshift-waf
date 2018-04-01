package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gomodule/redigo/redis"
)

var (
	Pool        *redis.Pool
	redisPrefix = "defender"
)

type DefenderLog struct {
	Time     int    `json:"time"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	URI      string `json:"uri"`
	Block    int    `json:"block"`
	Scores   struct {
		Sql             int `json:"sql"`
		LibInjectionXss int `json:"libinjection_xss"`
		Xss             int `json:"xss"`
		Rfi             int `json:"rfi"`
		Evade           int `json:"evade"`
		Traversal       int `json:"traversal"`
	} `json:"scores"`
	Match []struct {
		Zone    string `json:"zone"`
		ID      []int  `json:"id"`
		VarName string `json:"var_name"`
		Content string `json:"content"`
	} `json:"match"`
	Client      string `json:"client"`
	Server      string `json:"server"`
	Method      string `json:"method"`
	Protocol    string `json:"protocol"`
	UnparsedURI string `json:"unparsed_uri"`
}

func init() {
	redisHost := os.Getenv("REDIS_HOST")
	if redisHost == "" {
		redisHost = ":6379"
	}
	Pool = newPool(redisHost)
}

func parseTimestamp(ts string) time.Time {
	i, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		panic(err)
	}
	tm := time.Unix(i, 0)
	return tm
}

func newPool(server string) *redis.Pool {

	return &redis.Pool{

		MaxIdle:     3,
		IdleTimeout: 240 * time.Second,

		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp", server)
			if err != nil {
				return nil, err
			}
			return c, err
		},

		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			_, err := c.Do("PING")
			return err
		},
	}
}

func reader(out chan<- string) {
	consolescanner := bufio.NewScanner(os.Stdin)
	for consolescanner.Scan() {
		input := consolescanner.Text()
		out <- input
	}
	if err := consolescanner.Err(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func redisWriter(out chan<- string, in <-chan string) {
	conn := Pool.Get()
	defer conn.Close()
	for msg := range in {
		res := DefenderLog{}
		err := json.Unmarshal([]byte(msg), &res)
		if err != nil {
			// just ignore and continue
			continue
		}
		clientsKey := redisPrefix + ":clients:" + res.Client + ":"
		clientId, err := redis.Int(conn.Do("GET", clientsKey))
		if err != nil {
			fmt.Printf("Client does not exist: %s\n", err)
		}
		clientIdKey := fmt.Sprintf("%s:client:%d", redisPrefix, clientId)
		if clientId == 0 {
			// create the client key
			clientId, _ = redis.Int(conn.Do("INCR", redisPrefix+":client:id:"))
			clientIdKey = fmt.Sprintf("%s:client:%d", redisPrefix, clientId)
			fmt.Printf("ClientsID: %s\n", clientIdKey)
			conn.Send("MULTI")
			conn.Send("SET", clientsKey, clientId)
			conn.Send("HMSET", clientIdKey,
				"blocks", 0,
				"added", res.Time,
				"id", clientId,
				"ip", res.Client,
				"seen", res.Time)
			_, err := conn.Do("EXEC")
			if err != nil {
				fmt.Printf("Error creating client hash: %s\n", err)
				continue
			}
			fmt.Printf("Added client: %s - %d\n", clientsKey, clientId)
		}
		// Add the client to a zset, representing a set of events for client ip's
		conn.Do("ZADD", redisPrefix+":clientstimeline", res.Time, clientIdKey)

		// store the block
		blockId, _ := redis.Int(conn.Do("INCR", redisPrefix+":block:id:"))
		blockIdKey := fmt.Sprintf("%s:block:%d", redisPrefix, blockId)
		conn.Send("MULTI")
		conn.Send("HMSET", blockIdKey,
			"block", res.Block,
			"client", clientId,
			"added", res.Time,
			"hostname", res.Hostname,
			"method", res.Method,
			"uri", res.URI,
			"server", res.Server,
			"score.xss", res.Scores.Xss,
			"score.sql", res.Scores.Sql,
			"score.evade", res.Scores.Evade,
			"score.libinjectionxss", res.Scores.LibInjectionXss,
			"score.traversal", res.Scores.Traversal,
			"score.rfi", res.Scores.Rfi)
		conn.Send("Expire", blockIdKey, 864000)
		conn.Send("HINCRBY", clientIdKey, "blocks", 1)
		conn.Send("HSET", clientIdKey, "seen", res.Time)
		_, err = conn.Do("EXEC")
		if err != nil {
			fmt.Printf("Error creating block hash: %s\n", err)
			continue
		}
		// Add the block to timeline for the client
		clientBlockTimeline := fmt.Sprintf("%s:clientblocktimeline:%d", redisPrefix, clientId)
		conn.Do("ZADD", clientBlockTimeline, res.Time, blockIdKey)

		// Add matches
		for _, v := range res.Match {
			matchId, _ := redis.Int(conn.Do("INCR", redisPrefix+":match:id:"))
			matchIdKey := fmt.Sprintf("%s:match:%d", redisPrefix, matchId)
			conn.Do("HMSET", matchIdKey,
				"content", v.Content,
				"rule-id", v.ID,
				"varname", v.VarName,
				"zone", v.Zone,
				"clientid", clientId,
				"blockid", blockId)
			conn.Do("Expire", matchIdKey, 864000)
			// Add the match(es) to a sorted set so we can get them
			blockMatchTimeline := fmt.Sprintf("%s:blockmatchtimeline:%d", redisPrefix, blockId)
			conn.Do("ZADD", blockMatchTimeline, res.Time, matchIdKey)
		}
		if err != nil {
			fmt.Printf("Error creating block and match hash: %s\n", err)
		}
	}
}

func redisStatsPrinter() {
	// Run every 5 seconds and print stats
	conn := Pool.Get()
	defer conn.Close()
	for {
		time.Sleep(5 * time.Second)
		// Number of IP's stored
		ips, _ := redis.Int(conn.Do("ZCARD", "defender:clientstimeline"))
		recentIps, _ := redis.Strings(conn.Do("ZREVRANGE", "defender:clientstimeline", 0, 10))
		fmt.Println("------------------------")
		fmt.Printf("Known IP's: %d\n", ips)
		fmt.Println("Recent IP's:")
		for _, s := range recentIps {
			client, _ := redis.String(conn.Do("HGET", s, "ip"))
			clientId, _ := redis.String(conn.Do("HGET", s, "id"))
			blocks, _ := redis.Int(conn.Do("ZCARD", "defender:clientblocktimeline:"+clientId))
			fmt.Printf("\t%s (%d blocks)\n", client, blocks)
			fmt.Printf("\tRecent events for %s:\n", client)
			events, _ := redis.Strings(conn.Do("ZREVRANGE", "defender:clientblocktimeline:"+clientId, 0, 5))
			for _, event := range events {
				eventDetail, _ := redis.StringMap(conn.Do("HGETALL", event))
				fmt.Printf("\t\t%s\n", parseTimestamp(eventDetail["added"]))
				fmt.Printf("\t\tHostname: %s\n", eventDetail["hostname"])
				fmt.Printf("\t\tMethod: %s\n", eventDetail["method"])
				fmt.Printf("\t\tUri: %s\n", eventDetail["uri"])
				fmt.Printf("\t\tScores: xss=%s, sql=%s, evade=%s, libinjection_xss=%s, rfi=%s, traversal=%s\n",
					eventDetail["score.xss"],
					eventDetail["score.sql"],
					eventDetail["score.evade"],
					eventDetail["score.libinjectionxss"],
					eventDetail["score.rfi"],
					eventDetail["score.traversal"])
				fmt.Printf("\t\t+++++++++++++++++++++++++++++++\n")
			}
		}

	}
}

func main() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	msg := make(chan string, 1)
	res := make(chan string, 1)
	go reader(msg)
	go redisWriter(res, msg)
	go redisStatsPrinter()

loop:
	for {
		select {
		case <-sigs:
			fmt.Println("Got shutdown, exiting")
			Pool.Close()
			break loop
		case s := <-res:
			fmt.Println("Main:", s)
		}
	}
}
