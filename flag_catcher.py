from burp import IBurpExtender, IHttpListener
import re

class BurpExtender(IBurpExtender, IHttpListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Flag Catcher")
        callbacks.registerHttpListener(self)
        print("[Flag Catcher] Loaded - watching for flags")
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        
        try:
            response = messageInfo.getResponse()
            if not response:
                return
            
            body = self._helpers.bytesToString(response)
            
            # Compiled regex covering all requested formats (case-insensitive flag enabled at the end)
            # Formats included: bug, WEBVERSE, CTF, HTB, THM, PentesterLab, flag, picoCTF, RootMe
            pattern = r'(?:bug|WEBVERSE|CTF|HTB|THM|PLab|flag|picoCTF|RM)\{\w+\}'
            flags = re.findall(pattern, body, re.IGNORECASE)
            
            if flags:
                messageInfo.setHighlight("red")
                messageInfo.setComment("FLAG: " + ", ".join(flags))
                print("[FLAG FOUND] " + ", ".join(flags))
        
        except Exception as e:
            print("[Flag Catcher] Error: " + str(e))
