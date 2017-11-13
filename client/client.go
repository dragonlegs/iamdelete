package client


import (

	"github.com/op/go-logging"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"sync"
)

var log = logging.MustGetLogger("logger")
var sess *session.Session
var svc *iam.IAM
var dryrun bool
var UserList []*User

func getUser(wg *sync.WaitGroup,username string,number int){
	defer wg.Done()
	var Username User
	Username.Name = username
	UserList[number] = &Username
	log.Debugf("Gathering Details for User: %s", username)
	PopulateInformation(UserList[number])

}

func CheckingThis(profileName string, userList []string ,runIt bool)  {
	var wg sync.WaitGroup
	//log.Debug("Attempting to Use AccessKey and Secret key Values")
	dryrun = runIt
	if profileName != "" {
		sess = session.Must(session.NewSessionWithOptions(session.Options{
			Profile: profileName,
		}))
	}else {
		sess = session.Must(session.NewSession())
	}
	svc = iam.New(sess)
	log.Infof("User List: %s",userList)
	UserList = make([]*User,len(userList))
	for i,user := range userList{
		wg.Add(1)
		go getUser(&wg,user,i)
	}
	wg.Wait()
	log.Infof("Summary of Removal DRYRUN: %t",dryrun)
	for _,i := range UserList{
		log.Infof("%+v",i)
	}

}