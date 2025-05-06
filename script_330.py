class Module:
    def __init__(self, mainMenu, params=[]):
        self.info = {
            'Name': 'Open Safari in the background and play Thunderstruck.',
            'Author': ['@424f424f'],
            'Description': 'Open Safari in the background and play Thunderstruck.',
            'Background' : False,
            'OutputExtension' : "",
            'NeedsAdmin' : False,
            'OpsecSafe' : False,
            'Language' : 'python',
            'MinLanguageVersion' : '2.6',
            'Comments': ['']
        }
        self.options = {
            'Agent' : {
                'Description'   :   'Agent to run on.',
                'Required'      :   True,
                'Value'         :   ''
            }
        }
        self.mainMenu = mainMenu
        if params:
            for param in params:
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value
    def generate(self, obfuscate=False, obfuscationCommand=""):
        script = """
import subprocess
try:
    volume = \"""osascript -e "set Volume 100" ""\"
    process1 = subprocess.Popen(volume, stdout=subprocess.PIPE, shell=True)
    cmd = \"""open -a "Safari" -g -j https://www.youtube.com/watch?v=v2AC41dglnM""\"
    process2 = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    print "Thunderstruck engaged!"
except Exception as e:
    print "Module failed"
    print e
"""
        return script