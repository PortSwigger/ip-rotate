#AUTHOR: Dave Yesland @daveysec, Rhino Security Labs @rhinosecurity
#Burp Suite extension which uses AWS API Gateway to change your IP on every request to bypass IP blocking.
#More Info: https://rhinosecuritylabs.com/aws/bypassing-ip-based-blocking-aws/

from javax.swing import JPanel, JLabel, BoxLayout, JTextArea, JButton, JTextField
from burp import IBurpExtender, IExtensionStateListener, ITab, IHttpListener
from java.awt import GridLayout
import boto3
import re

DEBUG = True
EXT_NAME = 'Universal IP Rotator'
ENABLED = '<html><h2><font color="green">Enabled</font></h2></html>'
DISABLED = '<html><h2><font color="red">Disabled</font></h2></html>'
STAGE_NAME = 'proxy'
API_NAME = 'BurpAPI'
AVAIL_REGIONS = [
	"us-east-1","us-west-1","us-east-2",
	"us-west-2","eu-central-1","eu-west-1",
	"eu-west-2","eu-west-3","sa-east-1","eu-north-1"
]

class BurpExtender(IBurpExtender, IExtensionStateListener, ITab, IHttpListener):
	def __init__(self):
		self.allEndpoints = []
		self.currentEndpoint = 0
		self.gwIdsText = None
		self.target = None
		self.debug = DEBUG


	def registerExtenderCallbacks(self, callbacks):
		self.callbacks = callbacks
		self.helpers = callbacks.helpers
		self.isEnabled = False

		callbacks.registerHttpListener(self)
		callbacks.registerExtensionStateListener(self)
		callbacks.setExtensionName(EXT_NAME)
		callbacks.addSuiteTab(self)


	def getTargetProtocol(self):
		if self.https_button.isSelected() == True:
			return 'https'
		else:
			return 'http'


	#Called on "save" button click to save the settings
	def saveKeys(self, event):
		self.callbacks.saveExtensionSetting("gwIdsText", self.gateways_tbox.text)


	def enableGateway(self, event):
		for id_reg in self.gateways_tbox.text.split('\n'):
			id = id_reg.split(',')[0]
			reg = id_reg.split(',')[1]
			self.allEndpoints.append(id+'.execute-api.'+reg+'.amazonaws.com')

		self.isEnabled = True
		self.enable_button.setEnabled(False)
		self.disable_button.setEnabled(True)

		print 'Gateways enabled'
		print self.allEndpoints


	#Called on "Disable" button click to delete API Gateway
	def disableGateway(self, event):
		self.isEnabled = False
		self.enable_button.setEnabled(True)
		self.disable_button.setEnabled(False)
		del self.allEndpoints[:]
		print 'Gateways disabled'
		print self.allEndpoints


	#Traffic redirecting
	def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
		# only process requests
		if not messageIsRequest or not self.isEnabled:
			return

		# get the HTTP service for the request
		httpService = messageInfo.getHttpService()

		#Modify the request host, host header, and path to point to the new API endpoint
		#Should always use HTTPS because API Gateway only uses HTTPS
		if ':' in self.target_host_tbox.text: #hacky fix for https://github.com/RhinoSecurityLabs/IPRotate_Burp_Extension/issues/14
			host_no_port = self.target_host_tbox.text.split(':')[0]
			
		else:
			host_no_port = self.target_host_tbox.text

		if (host_no_port == httpService.getHost()):
			#Cycle through all the endpoints each request until then end of the list is reached
			if self.currentEndpoint < len(self.allEndpoints)-1:
				self.currentEndpoint += 1
			#Reset to 0 when end it reached
			else:
				self.currentEndpoint = 0
			
			if self.debug:
				print "====================================================="
				print messageInfo.getHttpService().getHost()
				print '-----------------------------------------------------'

			messageInfo.setHttpService(
				self.helpers.buildHttpService(
					self.allEndpoints[self.currentEndpoint],
					443, True
				)
			)
			if self.debug:
				print messageInfo.getHttpService().getHost()
				print "====================================================="

			requestInfo = self.helpers.analyzeRequest(messageInfo)
			new_headers = requestInfo.headers

			#Update the path to point to the API Gateway path
			req_head = new_headers[0]
			#hacky fix for https://github.com/RhinoSecurityLabs/IPRotate_Burp_Extension/issues/14
			if 'http://' in req_head or 'https://' in req_head:
				cur_path = re.findall('https?:\/\/.*?\/(.*) ',req_head)[0]
				new_headers[0] = re.sub(' (.*?) '," /"+STAGE_NAME+"/"+cur_path+" ",req_head)

			else:
				new_headers[0] = re.sub(' \/'," /"+STAGE_NAME+"/",req_head)

			#Replace the Host header with the Gateway host
			for header in new_headers:
				if header.startswith('Host: '):
					host_header_index = new_headers.index(header)
					new_headers[host_header_index] = 'Host: ' + messageInfo.getHttpService().getHost()

			#Update the headers insert the existing body
			body = messageInfo.request[requestInfo.getBodyOffset():len(messageInfo.request)]
			messageInfo.request = self.helpers.buildHttpMessage(
								new_headers,
								body
							)

	#Tab name
	def getTabCaption(self):
		return EXT_NAME

	#Handle extension unloading
	def extensionUnloaded(self):
		print "Extension unloaded"

	#Layout the UI
	def getUiComponent(self):
		gwIdsText = self.callbacks.loadExtensionSetting("gwIdsText")

		if gwIdsText:
			self.gwIdsText = gwIdsText

		self.panel = JPanel()
		self.main = JPanel()
		self.main.setLayout(BoxLayout(self.main, BoxLayout.Y_AXIS))

		self.gateways_panel = JPanel()
		self.main.add(self.gateways_panel)
		self.gateways_panel.setLayout(BoxLayout(self.gateways_panel, BoxLayout.X_AXIS))
		self.gateways_panel.add(JLabel('AWS API GW IDs: '))
		t = JTextArea()
		t.text = self.gwIdsText
		t.editable = True
		t.wrapStyleWord = True
		t.lineWrap = True
		t.size = (500, 200)
		self.gateways_tbox = t
		self.gateways_panel.add(self.gateways_tbox)

		self.target_panel = JPanel()
		self.main.add(self.target_panel)
		self.target_panel.setLayout(BoxLayout(self.target_panel, BoxLayout.X_AXIS))
		self.target_panel.add(JLabel('Target host: '))
		self.target_host_tbox = JTextField('ipinfo.io', 25)
		self.target_panel.add(self.target_host_tbox)
		
		self.buttons_panel = JPanel()
		self.main.add(self.buttons_panel)
		self.save_button = JButton('Save GW IDs', actionPerformed = self.saveKeys)
		self.buttons_panel.add(self.save_button)
		self.buttons_panel.setLayout(BoxLayout(self.buttons_panel, BoxLayout.X_AXIS))
		self.enable_button = JButton('Enable', actionPerformed = self.enableGateway)
		self.buttons_panel.add(self.enable_button)
		self.disable_button = JButton('Disable', actionPerformed = self.disableGateway)
		self.buttons_panel.add(self.disable_button)
		self.disable_button.setEnabled(False)
		
		self.panel.add(self.main)
		print "UI loaded"
		return self.panel
