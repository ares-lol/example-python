import ares

app_encrypted = [62410, 62414, 62411, 62410, 62410, 62410, 62366, 62362, 62418, 62409, 62414, 62414, 62364, 62418, 62411, 62407, 62410, 62410, 62418, 62366, 62409, 62413, 62406, 62418, 62362, 62411, 62415, 62406, 62361, 62412, 62366, 62363, 62407, 62407, 62365, 62409];

print('Connecting..')
session_ctx = ares.session_ctx(app_encrypted)
print('Connected!')

license_key = input('Enter your license: ')

response = session_ctx.authenticate(license_key)

if response != ares.response_e.VALID:
    if response == ares.response_e.HWID:
        print('HWID doesn\'t match!')
    if response == ares.response_e.BANNED:
        print('You\'re banned!')
    if response == ares.response_e.EXPIRED:
        print('Key is expired.')

    exit(0)

license = session_ctx.get_license()

variable = session_ctx.variable("windowshopper")

print(f'Valid!\nExpiry {license["expiry"]}\nDuration: {license["duration"]}\nHWID: {license["hwid"]}\nIP: {license["ip"]}\nStatus: {license["status"]}\nLast login: {license["lastLogin"]}\nVariable: {variable}')

image = session_ctx.module("70da57d7-da83-40e4-909f-4814fd2463ad")

for c in image.decrypt():
    print(f'{chr(c)}', end='')

print('\nDone!')