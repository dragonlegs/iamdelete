package main



import (
	"flag"
	"github.com/op/go-logging"
	"./client"
	"fmt"
	"strings"
)

var log = logging.MustGetLogger("logger")
var format = logging.MustStringFormatter(`%{color}%{time:15:04:05.000} ▶ %{level:.5s} %{id:03x}%{color:reset} %{message}`,)



func setuplogging(logLevel bool){

	logging.SetFormatter(format)
	if logLevel == true{

		logging.SetLevel(logging.DEBUG, "logger")
		log.Debug("DEBUG LOGGING ENABLED")
	}else{
		logging.SetLevel(logging.INFO,"logger")
	}

}

func helpmsg(){
	fmt.Println("Usage: iamdelete [options] testUser1,testUser2 \n")
	flag.PrintDefaults()

}

func main(){


	//accesskey := flag.String("accesskeyid","","Access Key ID")
	//secretkey := flag.String("secretaccesskey","","Secret Access Key")
	profileName := flag.String("profile","","AWS Profile to Use")
	dryrun := flag.Bool("dryrun",false,"Prints out Items to be deleted and does not delete them")
	logLevel := flag.Bool("d",false,"\n    	Enable Debug Logging")
	code := flag.Bool("code",false,"Check/Remove CodeCommit Keys Attached to IAM User")
	flag.Usage = helpmsg
	flag.Parse()
	setuplogging(*logLevel)
	log.Debug("Starting ClI")

	//list := flag.Args()
	if len(flag.Args()) <= 0 {
		helpmsg()
	}
	userList := strings.Split(flag.Args()[0],",")

	//for i := range list{
	//	log.Debugf("ARG: %d Value:%s ", i,flag.Arg(i))
	//}

	//if (*accesskey != "" && *secretkey != ""){
	//	log.Info("AccessKey and Secret Key Found Attempting To Verify")
	//	//client.CheckingThis(*accesskey,*secretkey)
	//}

	client.CheckingThis(*profileName,userList,*dryrun,*code)


}