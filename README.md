# OVH Graylog hook for logrus <img src="http://i.imgur.com/hTeVwmJ.png" width="40" height="40" alt=":walrus:" class="emoji" title=":walrus:"/>

## Usage

```
import (
    "github.com/sirupsen/logrus"
    "github.com/landru29/ovh-logrus-hook-graylog/grayloghook"
)


func main () {
    logger := logrus.New()
    graylogHost := "gra2.logs.ovh.com:12202"
    graylogToken := "here-is-my-token"
    logger.AddHook(grayloghook.NewGraylogHook(graylogHost, graylogToken, "example.org", &tls.Config{}))
    logger.Printf("[example]This is an example")
}
```