#!/usr/local/bin/python3.5

#import paramiko
import time
import sys
import os
import subprocess
import hc_module.ecss_config_http_commands as HT
import colorama
from colorama import Fore, Back, Style
import xml.etree.ElementTree as ET
import requests
import signal
import pjSIP_py.pjUA as pjua
import ssh_cocon.ssh_cocon as ccn


login = str(os.environ.get('COCON_USER'))
password = str(os.environ.get('COCON_PASS'))

host = str(os.environ.get('SSW_IP'))
port = int(os.environ.get('COCON_PORT'))

testingDomain = str(os.environ.get('VM_TEST_DOMAIN_NAME'))
testingDomainSIPport = str( int(os.environ.get('SSW_PORT'))+4 )
testingDomainSIPaddr = str(os.environ.get('SSW_IP'))
coreNode='core1@ecss1'
sipNode='sip1@ecss1'
dsNode='ds1@ecss1'
#sippPath = str(os.environ.get('SIPP_PATH'))
sippListenAddress=str(os.environ.get('VM_EXT_TRUNK_IP'))
sippListenPort='15076'
sippMediaListenPort='16016'
sippMediaListenPortTrunk='17016'

UACCount = 3
firstNumber = str(os.environ.get('VM_FIRST_NUMBER'))
secondNumber = str(int(firstNumber) + 1)
thirdNumber = str(int(firstNumber) + 2)
vmPassword = "1234"


masterSIPpass = str(os.environ.get('VM_FIRST_NUMBER'))
SIPgroup = str(os.environ.get('SIP_GROUP'))


colorama.init(autoreset=True)



def ssActivate(dom=testingDomain):
	print('Activating services...')	

	if not ccn.ssAddAccessAll(dom=testingDomain):
		return False

	if not ccn.ssEnable(dom=testingDomain,subscrNum=firstNumber,ssNames='voicemail chold ctr call_recording clip cnip'):
		return False
	if not ccn.ssEnable(dom=testingDomain,subscrNum=secondNumber,ssNames='chold ctr call_recording clip cnip'):
		return False

	if not ccn.ssActivation(dom=testingDomain,subscrNum=firstNumber,ssName='chold',ssOptions='dtmf_sequence_as_flash = false'):
		return False
	if not ccn.ssActivation(dom=testingDomain,subscrNum=firstNumber,ssName='ctr'):
		return False
	if not ccn.ssActivation(dom=testingDomain,subscrNum=firstNumber,ssName='clip'):
		return False
	if not ccn.ssActivation(dom=testingDomain,subscrNum=firstNumber,ssName='cnip'):
		return False
	if not ccn.ssActivation(dom=testingDomain,subscrNum=firstNumber,ssName='call_recording',ssOptions='mode = always_on'):
		return False
	if not ccn.ssActivation(dom=testingDomain,subscrNum=firstNumber,ssName='voicemail',ssOptions='timeout = 10'):
		return False

	if not ccn.ssActivation(dom=testingDomain,subscrNum=secondNumber,ssName='chold',ssOptions='dtmf_sequence_as_flash = false'):
		return False
	if not ccn.ssActivation(dom=testingDomain,subscrNum=secondNumber,ssName='ctr'):
		return False
	if not ccn.ssActivation(dom=testingDomain,subscrNum=secondNumber,ssName='clip'):
		return False
	if not ccn.ssActivation(dom=testingDomain,subscrNum=secondNumber,ssName='cnip'):
		return False
	if not ccn.ssActivation(dom=testingDomain,subscrNum=secondNumber,ssName='call_recording',ssOptions='mode = always_on'):
		return False

	return True


def checkVMMessages(dom,sipNumber,sipGroup):
	returnedFromSSH = ccn.executeOnSSH('domain/'+dom+'/alias/info '+ sipNumber +' '+ sipGroup +' '+ sipNumber +'@'+dom)
	print(returnedFromSSH)
	if 'Unread message(s): 1' in returnedFromSSH:
		return True
	else:
		return False


#############################################################################################

def preconfigure():
	cnt=0
	'''
	ctx= """<context domain=\""""+ testingDomain +"""\" digitmap="auto" name=\""""+ tcRoutingName+ """\">
    <rule name="tc">
    <conditions>
       <cdpn digits=\""""+ firstNumber +"""\"/>
    </conditions>
    <result>
       <teleconference/>
     </result>
    </rule>
    <rule name="toSIPpTrunk">
     <conditions>
       <cdpn digits=\""""+ tcClientNumberPrefix +"""%\"/>
     </conditions>
     <result>
        <external>
          <trunk value=\""""+tcExtTrunkName+"""\"/>
        </external>
     </result>
    </rule>
    <rule name="local_calls">
     <conditions>
       <cdpn digits="%"/>
     </conditions>
     <result>
        <local/>
     </result>
    </rule>
</context>"""

	'''

	###### - to be removed
	hRequests = HT.httpTerm(host=host,port='9999',login=login,passwd=password)

	if ccn.domainDeclare(testingDomain) :
		print(Fore.GREEN + 'Successful domain declare')
	else :
		print(Fore.RED + 'Smthing happen wrong with domain declaration...')
		return False

	cnt = 0
	time.sleep(2)
	while not ccn.checkDomainInit(testingDomain):					# проверяем инициализацию домена
		print(Fore.YELLOW + 'Not inited yet...')	
		cnt += 1
		if cnt > 5:
			print(Fore.RED + "Test domain wasn't inited :(")
			return False
		time.sleep(2)

	if ccn.sipTransportSetup(dom=testingDomain,sipIP=testingDomainSIPaddr,sipPort=testingDomainSIPport):
		print(Fore.GREEN + 'Successful SIP transport declare')
	else :
		print(Fore.RED + 'Smthing happen wrong with SIP network setup...')
		return False

	routingName = 'default_routing'
	if ccn.subscribersCreate(dom=testingDomain,sipNumber=firstNumber,sipPass=masterSIPpass,sipGroup=SIPgroup,routingCTX=routingName):
	 	print(Fore.GREEN + 'Successful VM subscriber creation')
	else:
		print(Fore.RED + 'Smthing happen wrong with subscribers creation...')
		return False

	if ccn.subscribersCreate(dom=testingDomain,sipNumber=secondNumber,sipPass=secondNumber,sipGroup=SIPgroup,routingCTX=routingName):
	 	print(Fore.GREEN + 'Successful Secondary subscriber creation')
	else:
		print(Fore.RED + 'Smthing happen wrong with subscriber creation...')
		return False

	if ccn.subscribersCreate(dom=testingDomain,sipNumber=thirdNumber,sipPass=thirdNumber,sipGroup=SIPgroup,routingCTX=routingName):
	 	print(Fore.GREEN + 'Successful Third subscriber creation')
	else:
		print(Fore.RED + 'Smthing happen wrong with subscriber creation...')
		return False
	
	if ssActivate(testingDomain):
		print(Fore.GREEN + 'Successful Services activated')
	else:
		print(Fore.RED + 'Smthing happen wrong activating services...')
		return False

	if ccn.setTraceMode(dom=testingDomain,traceMode='full_compressed'):
		print(Fore.GREEN + 'core traces successfully enabled')
	else:
		print(Fore.RED + 'Smthing happen wrong with changing core trace mode...')

	return True


def UACRegister():
	global subscrUA

	for i in range(0, UACCount):
		subscrNum = str(int(firstNumber)+i)
		if i == 0:
			autoAns = False  # autoanswer is false for subscriber with VM
		else:
			autoAns = True
		subscrUA.append(pjua.SubscriberUA(domain=testingDomain,username=subscrNum,passwd=subscrNum,sipProxy=testingDomainSIPaddr+':'+testingDomainSIPport,displayName='Test UA'+str(i),uaIP=sippListenAddress,regExpiresTimeout=900,autoAnswer=autoAns))

	print(Fore.GREEN + 'All UA Registered')

	allCliRegistered = False
	cnt = 0
	while not allCliRegistered:
		if cnt > 50:		
			print(Fore.RED + 'Some client UAs failed to register!')
			for i in range(0,UACCount):
				print(str(subscrUA[i].uaAccountInfo.uri) + ' state: ' + str(subscrUA[i].uaAccountInfo.reg_status) + ' - ' + str(subscrUA[i].uaAccountInfo.reg_reason))
			return False
		cnt += 1
		time.sleep(0.1)
		for i in range(0,UACCount):
			print('.', end='')
			if subscrUA[i].uaAccountInfo.reg_status != 200:
				allCliRegistered = False
				break
			else:
				allCliRegistered = True
	print('\n')
	print(Fore.GREEN + 'All UAC registered...')

	return True


def leaveVMTest(releseWithDTMF=False):
	global subscrUA
	cnt = 0
	vmMessageLeaveTimeout = 10
	callDuration = 30


	print(Style.BRIGHT + 'Now ' + subscrUA[1].uaAccountInfo.uri + ' will call to ' + subscrUA[0].uaAccountInfo.uri + ' and leave him a VM')

	subscrUA[1].makeCall(phoneURI=firstNumber+'@'+testingDomain)

	phase=0

	while cnt < callDuration:	
		time.sleep(1)
		print('.',end='')
		cnt += 1

		if phase == 0:
			if subscrUA[0].uaCurrentCallInfo.state == 3 and subscrUA[1].uaCurrentCallInfo.state == 3:
				phase=1
		elif phase == 1:
			if subscrUA[0].uaCurrentCallInfo.state == 6 and subscrUA[1].uaCurrentCallInfo.state == 5:
				phase=2
			if cnt > vmMessageLeaveTimeout+2:
				print(Fore.YELLOW + ' Still at ringing state, but expecting forwarding to VM!')
		elif phase == 2:
			pass

	cnt = 0
	if releseWithDTMF:
		subscrUA[1].sendInbandDTMF(dtmfDigit='#')
		print('DTMF # sent. Waiting for release from ssw...')
		while subscrUA[0].uaCurrentCallInfo.state != 6:
			cnt += 1
			if cnt > 5:
				print(Fore.RED +'SSW didnt released on DTMF')
				return False
	else:
		subscrUA[1].uaCurrentCall.hangup(code=200, reason='Release')

	if checkVMMessages(dom=testingDomain,sipNumber=firstNumber,sipGroup=SIPgroup):
		print(Fore.GREEN +'Message is succesful left')
		return True
	else:		
		return False

def checkVMbox():
	global subscrUA
	cnt = 0
	readMsgBefore = 0
	vmMessageLeaveTimeout = 10
	
	print(Style.BRIGHT + 'Now ' + subscrUA[0].uaAccountInfo.uri + ' will call to voiceMail *90# and check new message')
	subscrUA[0].makeCall(phoneURI='*90#@'+testingDomain)

	phase = 0

	print('waiting for answer...')
	cnt = 0
	Answered = False
	while cnt < 50:		
		time.sleep(0.1)
		if subscrUA[0].uaCurrentCallInfo.state == 5:
			Answered = True
			break			
		print('.',end='')		
		cnt += 1

	if not Answered:
		print(Fore.YELLOW +'Call not established')
		return False
	else:
		print('Call established')

	time.sleep(2)
	print('Dialing 1 and wait...')
	subscrUA[0].sendInbandDTMF(dtmfDigit='1')
	time.sleep(1)
	print('Dialing 1 and wait untill voice message listen...')
	subscrUA[0].sendInbandDTMF(dtmfDigit='1')

	cnt = 0
	callDuration = 20
	failed = False

	while cnt < callDuration:
		time.sleep(1)
		print('.',end='')
		cnt += 1	
		if subscrUA[0].uaCurrentCallInfo.state != 5:
			print(Fore.YELLOW + subscrUA[0].uaAccountInfo.uri + ' in wrong state!')
			failed = True

	if not failed:
		print('DTMF # sent. Waiting for release from ssw...')
		subscrUA[0].sendInbandDTMF(dtmfDigit='#')
	else:
		subscrUA[0].uaCurrentCall.hangup(code=200, reason='Release')
	
	while subscrUA[0].uaCurrentCallInfo.state != 6:
		cnt += 1
		time.sleep(0.1)
		print('.',end='')
		if cnt > 10:
			print(Fore.RED +'SSW didnt released on DTMF')
			return False

	

	returnedFromSSH = ccn.executeOnSSH('domain/'+testingDomain+'/alias/info '+ firstNumber +' '+ SIPgroup +' '+ firstNumber +'@'+testingDomain)
	print(returnedFromSSH)
	if 'Unread message(s): 0' in returnedFromSSH:
		print(Fore.GREEN +'Message successful read')
		return True
	else:
		return False

def callbackToVMcgpn():
	global subscrUA
	cnt = 0
	vmMessageLeaveTimeout = 10
	
	print(Style.BRIGHT + 'Now ' + subscrUA[0].uaAccountInfo.uri + ' will call to voiceMail *90# and check old message and call to its owner')
	subscrUA[0].makeCall(phoneURI='*90#@'+testingDomain)

	phase = 0

	print('waiting for answer...')
	cnt = 0
	Answered = False
	while cnt < 50:		
		time.sleep(0.1)
		if subscrUA[0].uaCurrentCallInfo.state == 5:
			Answered = True
			break			
		print('.',end='')		
		cnt += 1

	if not Answered:
		print(Fore.YELLOW +'Call not established')
		return False
	else:
		print('Call established')

	time.sleep(2)
	print('Dialing 1 and wait...')
	subscrUA[0].sendInbandDTMF(dtmfDigit='1')
	time.sleep(1)
	print('Dialing 2 for old message listen...')
	subscrUA[0].sendInbandDTMF(dtmfDigit='2')
	time.sleep(3)
	print('Dialing 8 for callback...')
	subscrUA[0].sendInbandDTMF(dtmfDigit='8')
	time.sleep(4)

	if subscrUA[0].uaCurrentCallInfo.state != 5:
		print(Fore.YELLOW +'Subscriber ' + subscrUA[0].uaAccountInfo.uri + ' is not in call state')
		subscrUA[0].uaCurrentCall.hangup(code=200, reason='Release')
		subscrUA[1].uaCurrentCall.hangup(code=200, reason='Release')
		return False

	
	cnt = 0
	Answered = False
	while cnt < 70:
		time.sleep(0.1)
		if subscrUA[1].uaCurrentCallInfo.state == 5:
			Answered = True
			break			
		print('.',end='')		
		cnt += 1

	if not Answered:
		print(Fore.YELLOW +'Subscriber ' + subscrUA[1].uaAccountInfo.uri + ' is not in call state')
		subscrUA[0].uaCurrentCall.hangup(code=200, reason='Release')
		#subscrUA[1].uaCurrentCall.hangup(code=200, reason='Release')
		return False
	else:
		print('Call successful established')
	

	print('Releasing call...')
	subscrUA[0].uaCurrentCall.hangup(code=200, reason='Release')
	time.sleep(1)

	if subscrUA[1].uaCurrentCallInfo.state == 5:
		print(Fore.YELLOW +'Subscriber ' + subscrUA[1].uaAccountInfo.uri + ' is not released')
		#subscrUA[0].uaCurrentCall.hangup(code=200, reason='Release')
		subscrUA[1].uaCurrentCall.hangup(code=200, reason='Release')
		return False

	return True


def setVMPasswd():
	global subscrUA
	print(Style.BRIGHT + 'Now ' + subscrUA[0].uaAccountInfo.uri + ' will call to voiceMail *90# and set new password')
	subscrUA[0].makeCall(phoneURI='*90#@'+testingDomain)

	phase = 0

	print('waiting for answer...')
	cnt = 0
	Answered = False
	while cnt < 50:		
		time.sleep(0.1)
		if subscrUA[0].uaCurrentCallInfo.state == 5:
			Answered = True
			break			
		print('.',end='')		
		cnt += 1

	if not Answered:
		print('Call not established')
		return False
	else:
		print('Call established')

	time.sleep(2)
	print('Dialing 2 and wait...')
	subscrUA[0].sendInbandDTMF(dtmfDigit='2')
	time.sleep(2)
	print('Dialing 2 and wait...')
	subscrUA[0].sendInbandDTMF(dtmfDigit='2')
	time.sleep(2)
	print('Dialing 1 and wait...')
	subscrUA[0].sendInbandDTMF(dtmfDigit='1')
	time.sleep(2)
	print('Dialing old password # and wait...')
	subscrUA[0].sendInbandDTMF(dtmfDigit='#')
	time.sleep(2)
	print('Dialing new password '+ vmPassword +' and wait...')
	for k in range(0,len(vmPassword)):
		print('Dialing ' + vmPassword[k])
		subscrUA[0].sendInbandDTMF(dtmfDigit=vmPassword[k])
		time.sleep(1)

	print('Dialing #')
	subscrUA[0].sendInbandDTMF(dtmfDigit='#')
	time.sleep(2)
	print('Dialing confirm new password '+ vmPassword +' and wait...')
	for k in range(0,len(vmPassword)):
		print('Dialing ' + vmPassword[k])
		subscrUA[0].sendInbandDTMF(dtmfDigit=vmPassword[k])
		time.sleep(1)
	print('Dialing #')
	subscrUA[0].sendInbandDTMF(dtmfDigit='#')

	time.sleep(2)
	if subscrUA[0].uaCurrentCallInfo.state != 5:
		print(Fore.RED + subscrUA[0].uaAccountInfo.uri + ' in wrong state!')
		return False

	print('Releasing from VM menu')
	subscrUA[0].uaCurrentCall.hangup(code=200, reason='Release')
	time.sleep(2)

	returnedFromSSH = ccn.executeOnSSH('domain/'+ testingDomain +'/ss/info ' + firstNumber)
	print(returnedFromSSH)

	if 'password = "1234"' in returnedFromSSH:
		print(Fore.GREEN + 'It seems that password for VM is set')
		return True
	else:
		return False
	return True

def removeVMPasswd():
	global subscrUA
	print(Style.BRIGHT + 'Now ' + subscrUA[0].uaAccountInfo.uri + ' will call to voiceMail *90# and remove VM password')
	subscrUA[0].makeCall(phoneURI='*90#@'+testingDomain)

	phase = 0

	print('waiting for answer...')
	cnt = 0
	Answered = False
	while cnt < 50:		
		time.sleep(0.1)
		if subscrUA[0].uaCurrentCallInfo.state == 5:
			Answered = True
			break			
		print('.',end='')		
		cnt += 1

	if not Answered:
		print('Call not established')
		return False
	else:
		print('Call established')

	print('Dialing VM password')
	time.sleep(2)
	for k in range(0,len(vmPassword)):
		print('Dialing ' + vmPassword[k])
		subscrUA[0].sendInbandDTMF(dtmfDigit=vmPassword[k])
		time.sleep(1)


	time.sleep(2)
	print('Dialing 2 and wait...')
	subscrUA[0].sendInbandDTMF(dtmfDigit='2')
	time.sleep(2)
	print('Dialing 2 and wait...')
	subscrUA[0].sendInbandDTMF(dtmfDigit='2')
	time.sleep(2)
	print('Dialing 1 and wait...')
	subscrUA[0].sendInbandDTMF(dtmfDigit='1')
	time.sleep(2)
	print('Dialing old password 1234 # and wait...')
	for k in range(0,len(vmPassword)):
		print('Dialing ' + vmPassword[k])
		subscrUA[0].sendInbandDTMF(dtmfDigit=vmPassword[k])
		time.sleep(1)
	print('Dialing #')
	subscrUA[0].sendInbandDTMF(dtmfDigit='#')
	time.sleep(2)
	print('Dialing new password # and wait...')
	subscrUA[0].sendInbandDTMF(dtmfDigit='#')
	time.sleep(2)
	print('Dialing confirm new password # and wait...')
	subscrUA[0].sendInbandDTMF(dtmfDigit='#')
	time.sleep(2)

	if subscrUA[0].uaCurrentCallInfo.state != 5:
		print(Fore.RED + subscrUA[0].uaAccountInfo.uri + ' in wrong state!')
		return False

	print('Releasing from VM menu')
	subscrUA[0].uaCurrentCall.hangup(code=200, reason='Release')
	time.sleep(2)

	returnedFromSSH = ccn.executeOnSSH('domain/'+ testingDomain +'/ss/info ' + firstNumber)
	print(returnedFromSSH)

	if 'password = []' in returnedFromSSH:
		print(Fore.GREEN + 'It seems that password for VM is removed')
		return True
	else:
		return False
	return True


def getVMfromExtNumber():
	global subscrUA
	print(Style.BRIGHT + 'Now ' + subscrUA[1].uaAccountInfo.uri + ' will call to remote voiceMail *91# ')
	subscrUA[1].makeCall(phoneURI='*91#@'+testingDomain)

	phase = 0

	print('waiting for answer...')
	cnt = 0
	Answered = False
	while cnt < 50:		
		time.sleep(0.1)
		if subscrUA[1].uaCurrentCallInfo.state == 5:
			Answered = True
			break			
		print('.',end='')		
		cnt += 1

	if not Answered:
		print('Call not established')
		return False
	else:
		print('Call established')

	time.sleep(2)
	print('Dialing remote number...')
	print('Dialing 1...')
	subscrUA[1].sendInbandDTMF(dtmfDigit='1')
	time.sleep(1)
	print('Dialing 5...')
	subscrUA[1].sendInbandDTMF(dtmfDigit='5')
	time.sleep(1)
	print('Dialing 1...')
	subscrUA[1].sendInbandDTMF(dtmfDigit='1')
	time.sleep(1)
	print('Dialing 0...')
	subscrUA[1].sendInbandDTMF(dtmfDigit='0')
	time.sleep(1)
	print('Dialing #')
	subscrUA[1].sendInbandDTMF(dtmfDigit='#')
	time.sleep(3)
	if subscrUA[1].uaCurrentCallInfo.state != 5:
		print(Fore.RED + 'The call was released for some reason')
		return False
	print('Dialing password...')
	for k in range(0,len(vmPassword)):
		print('Dialing ' + vmPassword[k])
		subscrUA[0].sendInbandDTMF(dtmfDigit=vmPassword[k])
		time.sleep(1)
	time.sleep(3)

	if subscrUA[1].uaCurrentCallInfo.state != 5:
		print(Fore.RED + 'The call was released for some reason')
		return False

	print('Dialing # for exit from VM...')
	subscrUA[1].sendInbandDTMF(dtmfDigit='#')
	time.sleep(2)

	if subscrUA[1].uaCurrentCallInfo.state == 5:
		print(Fore.RED + 'The call was not released')
		subscrUA[1].uaCurrentCall.hangup(code=200, reason='Release')		
		return False

	return True

def getVMfromExtNumberType2():
	global subscrUA
	print(Style.BRIGHT + 'Now ' + subscrUA[1].uaAccountInfo.uri + ' will call to remote voiceMail *91*1510# ')
	subscrUA[1].makeCall(phoneURI='*91*1510#@'+testingDomain)

	phase = 0

	print('waiting for answer...')
	cnt = 0
	Answered = False
	while cnt < 50:		
		time.sleep(0.1)
		if subscrUA[1].uaCurrentCallInfo.state == 5:
			Answered = True
			break			
		print('.',end='')		
		cnt += 1

	if not Answered:
		print('Call not established')
		return False
	else:
		print('Call established')

	time.sleep(2)
	print('Dialing password...')
	for k in range(0,len(vmPassword)):
		print('Dialing ' + vmPassword[k])
		subscrUA[0].sendInbandDTMF(dtmfDigit=vmPassword[k])
		time.sleep(1)
	time.sleep(3)

	if subscrUA[1].uaCurrentCallInfo.state != 5:
		print(Fore.RED + 'The call was released for some reason')
		return False

	print('Dialing # for exit from VM...')
	subscrUA[1].sendInbandDTMF(dtmfDigit='#')
	time.sleep(2)

	if subscrUA[1].uaCurrentCallInfo.state == 5:
		print(Fore.RED + 'The call was not released')
		subscrUA[1].uaCurrentCall.hangup(code=200, reason='Release')		
		return False

	return True

def VMleaveOnBusy():
	global subscrUA
	cnt = 0
	vmMessageLeaveTimeout = 15
	callDuration = 30

	print(Style.BRIGHT +'Setting busy property')
	
	if not ccn.ssActivation(dom=testingDomain,subscrNum=firstNumber,ssName='voicemail',ssOptions='busy = true'):
		print(Fore.RED + 'Change "busy" property failed')
		return False

	print(Style.BRIGHT +'Now ' + subscrUA[0].uaAccountInfo.uri + ' will call to ' + subscrUA[2].uaAccountInfo.uri + ' to make him self busy')

	subscrUA[0].makeCall(phoneURI=thirdNumber+'@'+testingDomain)
	cnt = 0
	Answered = False
	while cnt < 50:		
		time.sleep(0.1)
		if subscrUA[2].uaCurrentCallInfo.state == 5:
			Answered = True
			break			
		print('.',end='')		
		cnt += 1
	if not Answered:
		print('Call not established')
		return False
	else:
		print('Call established')

	time.sleep(3)

	print(Style.BRIGHT +'Now ' + subscrUA[1].uaAccountInfo.uri + ' will call to ' + subscrUA[0].uaAccountInfo.uri + ' and leave him a VM as busy')

	subscrUA[1].makeCall(phoneURI=firstNumber+'@'+testingDomain)

	cnt = 0
	Answered = False
	while cnt < 50:		
		time.sleep(0.1)
		if subscrUA[1].uaCurrentCallInfo.state == 5:
			Answered = True
			break
		if subscrUA[0].uaCurrentCallInfo.state != 5:
			print('VM subscriber have changed state on '+  subscrUA[1].uaAccountInfo.uri + ' incoming call')
			subscrUA[0].uaCurrentCall.hangup(code=200, reason='Release')
			subscrUA[1].uaCurrentCall.hangup(code=200, reason='Release')
			return False
		print('.',end='')		
		cnt += 1
	if not Answered:
		print('Call not established')
		return False
	else:
		print('Call established')


	cnt = 0
	while cnt < vmMessageLeaveTimeout:
		time.sleep(1)
		print('.',end='')
		cnt += 1	
		if subscrUA[1].uaCurrentCallInfo.state != 5:
			print(Fore.YELLOW + subscrUA[0].uaAccountInfo.uri + ' in wrong state!')
			failed = True

	print(Style.BRIGHT +'VM message left, hanging up')
	subscrUA[1].uaCurrentCall.hangup(code=200, reason='Release')
	subscrUA[0].uaCurrentCall.hangup(code=200, reason='Release')


	time.sleep(1)
	print(Style.BRIGHT +'Reset VM properties')


	if not ccn.ssActivation(dom=testingDomain,subscrNum=firstNumber,ssName='voicemail',ssOptions='busy = false'):
		print(Fore.RED + 'Change "busy" property failed')
		return False

	if checkVMMessages(dom=testingDomain,sipNumber=firstNumber,sipGroup=SIPgroup):
		print(Fore.GREEN +'Message is succesful left')
		return True
	else:		
		return False

def VMleaveUnconditional():
	global subscrUA
	cnt = 0
	vmMessageLeaveTimeout = 15
	callDuration = 30

	print(Style.BRIGHT +'Setting unconditional property')

	if not ccn.ssActivation(dom=testingDomain,subscrNum=firstNumber,ssName='voicemail',ssOptions='unconditional = true'):
		print(Fore.RED + 'Change "unconditional" property failed')
		return False

	print(Style.BRIGHT +'Now ' + subscrUA[1].uaAccountInfo.uri + ' will call to ' + subscrUA[0].uaAccountInfo.uri + ' and leave him a VM unconditional')

	subscrUA[1].makeCall(phoneURI=firstNumber+'@'+testingDomain)

	cnt = 0
	Answered = False
	while cnt < 50:		
		time.sleep(0.1)
		if subscrUA[1].uaCurrentCallInfo.state == 5:
			Answered = True
			break
		if subscrUA[0].uaCurrentCallInfo.state in range(1,5):
			print('VM subscriber in wrong state')
			subscrUA[1].uaCurrentCall.hangup(code=200, reason='Release')
			return False
		print('.',end='')		
		cnt += 1
	if not Answered:
		print('Call not established')
		return False
	else:
		print('Call established')


	cnt = 0
	while cnt < vmMessageLeaveTimeout:
		time.sleep(1)
		print('.',end='')
		cnt += 1	
		if subscrUA[1].uaCurrentCallInfo.state != 5:
			print(Fore.YELLOW + subscrUA[0].uaAccountInfo.uri + ' in wrong state!')
			failed = True

	print(Style.BRIGHT +'VM message left, hanging up')
	subscrUA[1].uaCurrentCall.hangup(code=200, reason='Release')

	time.sleep(1)
	print(Style.BRIGHT +'Reset VM properties')

	if not ccn.ssActivation(dom=testingDomain,subscrNum=firstNumber,ssName='voicemail',ssOptions='unconditional = false'):
		print(Fore.RED + 'Change "unconditional" property failed')
		return False

	if checkVMMessages(dom=testingDomain,sipNumber=firstNumber,sipGroup=SIPgroup):
		print(Fore.GREEN +'Message is succesful left')
		return True
	else:		
		return False

def VMleaveOnUnavailable():
	global subscrUA
	cnt = 0
	vmMessageLeaveTimeout = 15
	callDuration = 30

	print(Style.BRIGHT +'Setting out_of_service property')

	if not ccn.ssActivation(dom=testingDomain,subscrNum=firstNumber,ssName='voicemail',ssOptions='out_of_service = true'):
		print(Fore.RED + 'Change "out_of_service" property failed')
		return False

	print('Unregistering VM subscriber')
	subscrUA[0].acc.set_registration(renew=False)

	time.sleep(1)

	ccn.subscriberSipInfo(dom=testingDomain,sipNumber=firstNumber,sipGroup=SIPgroup,complete=False)

	print(Style.BRIGHT +'Now ' + subscrUA[1].uaAccountInfo.uri + ' will call to ' + subscrUA[0].uaAccountInfo.uri + ' and leave him a VM')

	subscrUA[1].makeCall(phoneURI=firstNumber+'@'+testingDomain)

	cnt = 0
	Answered = False
	while cnt < 50:		
		time.sleep(0.1)
		if subscrUA[1].uaCurrentCallInfo.state == 5:
			Answered = True
			break
		print('.',end='')		
		cnt += 1
	if not Answered:
		print('Call not established')
		return False
	else:
		print('Call established')


	cnt = 0
	while cnt < vmMessageLeaveTimeout:
		time.sleep(1)
		print('.',end='')
		cnt += 1	
		if subscrUA[1].uaCurrentCallInfo.state != 5:
			print(Fore.YELLOW + subscrUA[0].uaAccountInfo.uri + ' in wrong state!')
			failed = True

	print(Style.BRIGHT +'VM message left, hanging up')
	subscrUA[1].uaCurrentCall.hangup(code=200, reason='Release')

	time.sleep(1)
	print(Style.BRIGHT +'Reset VM properties')


	if not ccn.ssActivation(dom=testingDomain,subscrNum=firstNumber,ssName='voicemail',ssOptions='out_of_service = false'):
		print(Fore.RED + 'Change "out_of_service" property failed')
		return False

	print('Reset VM subscriber registration')
	subscrUA[0].acc.set_registration(renew=True)
	time.sleep(1)

	ccn.subscriberSipInfo(dom=testingDomain,sipNumber=firstNumber,sipGroup=SIPgroup,complete=False)

	if checkVMMessages(dom=testingDomain,sipNumber=firstNumber,sipGroup=SIPgroup):
		print(Fore.GREEN +'Message is succesful left')
		return True
	else:		
		return False


def VMpropertyChange(VMpropertyName,enabling=True):
	global subscrUA

	if VMpropertyName is 'play_message_details':
		secondDigit = '2'
		thirdDigit = '3'
	elif VMpropertyName is 'send_by_email':
		secondDigit = '2'
		thirdDigit = '2'
	elif VMpropertyName is 'no_reply':
		secondDigit = '1'
		thirdDigit = '1'
	elif VMpropertyName is 'busy':
		secondDigit = '1'
		thirdDigit = '2'
	elif VMpropertyName is 'out_of_service':
		secondDigit = '1'
		thirdDigit = '3'
	elif VMpropertyName is 'unconditional':
		secondDigit = '1'
		thirdDigit = '4'
	else:
		print('Invalid property name ' + VMpropertyName)
		return False

	print('Now ' + subscrUA[0].uaAccountInfo.uri + ' will call to voiceMail *90# to change property '+ VMpropertyName + ' to '+ str(enabling))
	subscrUA[0].makeCall(phoneURI='*90#@'+testingDomain)

	print('waiting for answer...')
	cnt = 0
	Answered = False
	while cnt < 50:		
		time.sleep(0.1)
		if subscrUA[0].uaCurrentCallInfo.state == 5:
			Answered = True
			break			
		print('.',end='')		
		cnt += 1

	if not Answered:
		print(Fore.YELLOW +'Call not established')
		return False
	else:
		print('Call established')

	time.sleep(2)
	print('Dialing 2 and wait...')
	subscrUA[0].sendInbandDTMF(dtmfDigit='2')
	time.sleep(2)
	print('Dialing '+secondDigit+' and wait...')
	subscrUA[0].sendInbandDTMF(dtmfDigit=secondDigit)
	time.sleep(2)
	print('Dialing '+thirdDigit+' and wait...')
	subscrUA[0].sendInbandDTMF(dtmfDigit=thirdDigit)
	time.sleep(2)

	if enabling:
		dialDigit = '1'
		checkStr = VMpropertyName + ' = true'
	else:
		dialDigit = '2'
		checkStr = VMpropertyName +' = false'

	print('Dialing '+dialDigit+' to change '+VMpropertyName+' mode...')
	subscrUA[0].sendInbandDTMF(dtmfDigit=dialDigit)
	time.sleep(3)

	print('Dialing # for exit from VM...')
	subscrUA[0].sendInbandDTMF(dtmfDigit='#')
	time.sleep(2)

	if subscrUA[0].uaCurrentCallInfo.state == 5:
		print(Fore.RED + 'The call was not released')
		subscrUA[0].uaCurrentCall.hangup(code=200, reason='Release')		
		return False

	returnedFromSSH = ccn.executeOnSSH('domain/'+ testingDomain +'/ss/info ' + firstNumber)
	print(returnedFromSSH)

	if checkStr in returnedFromSSH:
		print(Fore.GREEN + 'It seems that ' + VMpropertyName + ' is changed to ' + checkStr)
	else:
		print(Fore.RED + 'Something wrong with ' + VMpropertyName + ' property change')
		return False

	return True

def testHeader(headerText,headerColoramaColor=Style.BRIGHT):
	for i in range(len(headerText)+4):
		print(headerColoramaColor + '=', end='')
	print('')
	print(headerColoramaColor + '  ' + headerText)
	for i in range(len(headerText)+4):
		print(headerColoramaColor + '=', end='')
	print('')


#############################################################################################

subscrUA = []
firstUA = 0
secondUA = 0
thirdUA = 0
failure = False
testReport = []

#'''
testHeader('-Start preconfiguration test-')
if not preconfigure():
	print(Fore.RED + 'Preconfiguration test failed')
	failure = False
	sys.exit(1)
else:
	resStr = '-Start preconfiguration done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)
#'''

testHeader('-Starting register test-')
if not UACRegister():
	resStr = 'Register test failed'
	print(Fore.RED + resStr)
	failure = False
	sys.exit(1)
else:
	resStr = '-Register test done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)
#'''

#'''
testHeader('-Start leaving VM on no reply test-')
if not leaveVMTest():
	resStr = 'Leaving VM on no reply test failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-Leaving VM on no reply test done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)

testHeader('-Checking VM message test-')
if not checkVMbox():
	resStr = 'Checking VM test failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-Checking VM test done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)
######################
testHeader('-Start leaving message on busy test-')
if not VMleaveOnBusy():
	resStr = 'Leaving VM on busy test failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-Leaving VM on busy test done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)

testHeader('-Checking VM message test-')
if not checkVMbox():
	resStr = 'Checking VM test failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-Checking VM test done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)

######################
testHeader('-Start leaving message unconditional test-')
if not VMleaveUnconditional():
	resStr = 'Leaving VM unconditional test failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-Leaving VM unconditional test done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)

testHeader('-Checking VM message test-')
if not checkVMbox():
	resStr = 'Checking VM test failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-Checking VM test done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)

######################
testHeader('-Start leaving message on out of service test-')
if not VMleaveOnUnavailable():
	resStr = 'Leaving VM out of service test failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-Leaving VM out of service test done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)

testHeader('-Checking VM message test-')
if not checkVMbox():
	resStr = 'Checking VM test failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-Checking VM test done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)
######################

testHeader('-Callback to VM owner test-')
if not callbackToVMcgpn():
	resStr = 'Callback to VM owner test failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-Callback to VM owner test done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)


testHeader('-Testing VM password set-')
if not setVMPasswd():
	resStr = 'VM Password set test failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-VM Password set test done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)


testHeader('-Testing remote acccess to VM-')
if not getVMfromExtNumber():
	resStr = 'Remote access to VM failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-Remote access to VM success!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)

testHeader('-Testing remote acccess to VM type 2-')
if not getVMfromExtNumberType2():
	resStr = 'Remote access to VM type 2 failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-Remote access to VM type 2 success!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)


testHeader('-Testing VM password remove-')
if not removeVMPasswd():
	resStr = 'VM Password remove test failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-VM Password remove test done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)	


################# send_by_email
testHeader('-Testing email property set to true-')
if not VMpropertyChange(VMpropertyName='send_by_email',enabling=True):
	resStr = 'VM email property set to true failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-VM email property set to true test done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)

testHeader('-Testing email property set to false-')
if not VMpropertyChange(VMpropertyName='send_by_email',enabling=False):
	resStr = 'VM email property set to false failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-VM email property set to false test done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)
################# play_message_details
testHeader('-Testing play_message_details property set to true-')
if not VMpropertyChange(VMpropertyName='play_message_details',enabling=True):
	resStr = 'VM play_message_details property set to true failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-VM play_message_details property set to true test done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)

testHeader('-Testing play_message_details property set to false-')
if not VMpropertyChange(VMpropertyName='play_message_details',enabling=False):
	resStr = 'VM play_message_details property set to false failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-VM play_message_details property set to false test done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)
################# busy
testHeader('-Testing busy property set to true-')
if not VMpropertyChange(VMpropertyName='busy',enabling=True):
	resStr = 'VM busy property set to true test failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-VM busy property set to true test done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)

testHeader('-Testing busy property set to false-')
if not VMpropertyChange(VMpropertyName='busy',enabling=False):
	resStr = 'VM busy property set to false test failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-VM busy property set to false test done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)
################# no_reply
testHeader('-Testing no_reply property set to false-')
if not VMpropertyChange(VMpropertyName='no_reply',enabling=False):
	resStr = 'VM no_reply property set to true false failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-VM no_reply property set to false done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)

testHeader('-Testing no_reply property set to True-')
if not VMpropertyChange(VMpropertyName='no_reply',enabling=True):
	resStr = 'VM no_reply property set to True failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-VM no_reply property set to True done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)
################# out_of_service
testHeader('-Testing out_of_service property set to false-')
if not VMpropertyChange(VMpropertyName='out_of_service',enabling=True):
	resStr = 'VM out_of_service property set to false test failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-VM out_of_service property set to false test done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)

testHeader('-Testing out_of_service property set to True-')
if not VMpropertyChange(VMpropertyName='out_of_service',enabling=False):
	resStr = 'VM out_of_service property set to True failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-VM out_of_service property set to True done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)
################# unconditional
testHeader('-Testing unconditional property set to true-')
if not VMpropertyChange(VMpropertyName='unconditional',enabling=True):
	resStr = 'VM unconditional property set to true test failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-VM unconditional property set to true test done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)

testHeader('-Testing unconditional property set to false-')
if not VMpropertyChange(VMpropertyName='unconditional',enabling=False):
	resStr = 'VM unconditional property set to false failed'
	print(Fore.RED + resStr)
	failure = False
	testReport.append(resStr)
	#sys.exit(1)
else:
	resStr = '-VM unconditional property set to false done!-'
	print(Fore.GREEN + resStr)
	testReport.append(resStr)
	time.sleep(1)
#


#client.close()

print(Style.BRIGHT + 'Total Results of Voice Mail tests:')
for reportStr in testReport:
	print(reportStr)


if failure:
	print(Fore.RED +'Some tests failed!')
	sys.exit(1)
else:
	print(Fore.GREEN +'It seems to be all FINE...')
	print('We did it!!')
	sys.exit(0)