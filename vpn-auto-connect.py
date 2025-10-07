"""
Autor: Rafael Costa Biasi [https://github.com/rafaelbiasi]
Versão: 1.0.11
"""

import argparse
import base64
import getpass
import json
import os
import subprocess
import time

from urllib.parse import urlparse
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = None


def encrypt_password(password, sudo_password, salt):
    key = get_encode_driver(salt, sudo_password)

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_password = padder.update(password.encode()) + padder.finalize()
    encrypted_password = encryptor.update(padded_password) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_password).decode()


def decrypt_password(encrypted_password, sudo_password, salt):
    key = get_encode_driver(salt, sudo_password)

    encrypted_data = base64.b64decode(encrypted_password)
    iv = encrypted_data[:16]
    encrypted_password = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_password = decryptor.update(encrypted_password) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    password = unpadder.update(padded_password) + unpadder.finalize()
    return password.decode()


def get_encode_driver(salt, sudo_password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(sudo_password.encode())
    return key


def load_config():
    print('Carregando configuração.')
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)


def save_config(config):
    print('Salvando configuração.')
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)


def install_packages():
    print('Instalando dependências.')
    run_sudo_command(['apt', 'update'])
    run_sudo_command(['apt', 'install', '-y', 'openconnect', 'openssl'])
    subprocess.run(['pip3', 'install', 'selenium', 'webdriver_manager', 'cryptography'], check=True)
    run_sudo_command(['pip3', 'install', 'vpn-slice[dnspython,setproctitle]'])


def configure_driver(args):
    print('Configurando web driver.')
    chrome_options = webdriver.ChromeOptions()
    if not args.manual and not args.browser:
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--window-size=720,540')
    chrome_options.add_argument('--ignore-certificate-errors')
    chrome_options.add_argument('--ignore-ssl-errors')
    driver_path = "/home/rafaelbiasi/.wdm/drivers/chromedriver/linux64/chromedriver-linux64/chromedriver"
    return webdriver.Chrome(service=ChromeService(driver_path), options=chrome_options)
#    return webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=chrome_options)


def wait_for_page_load(driver, timeout=30):
    print('Esperando página carregar.')
    WebDriverWait(driver, timeout).until(
        lambda d: d.execute_script('return document.readyState') == 'complete'
    )
    time.sleep(1)


def automate_login(driver, host, username, password):
    print('Login automático.')
    driver.get(host)
    if not wait_for_initial_load_with_refresh(driver, timeout_per_attempt=15, max_refreshes=5):
        print('Falha ao carregar a página inicial após 5 refreshs. Encerrando.')
        driver.quit()
        raise SystemExit(1)

    # Login - Start
    # Login - "Email" Screen
    email_field = WebDriverWait(driver, 30).until(
        EC.element_to_be_clickable((By.NAME, "loginfmt"))
    )
    email_field.clear()
    email_field.send_keys(username)

    next_button = WebDriverWait(driver, 30).until(
        EC.element_to_be_clickable((By.ID, "idSIButton9"))
    )
    next_button.click()
    wait_for_page_load(driver)

    # Login - "Password" Screen
    password_field = WebDriverWait(driver, 30).until(
        EC.element_to_be_clickable((By.NAME, "passwd"))
    )
    password_field.clear()
    password_field.send_keys(password)

    sign_in_button = WebDriverWait(driver, 30).until(
        EC.element_to_be_clickable((By.ID, "idSIButton9"))
    )
    sign_in_button.click()
    wait_for_page_load(driver)

    current_netloc = urlparse(driver.current_url).netloc.split(':')[0].lower()
    kmsi_domain = 'login.microsoftonline.com'

    if current_netloc == kmsi_domain:
        # Login - "Don't ask me again" Screen (opcional)
        try:
            dont_show_checkbox = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.ID, "KmsiCheckboxField"))
            )
            dont_show_checkbox.click()

            yes_button = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.ID, "idSIButton9"))
            )
            yes_button.click()
            print('Tela "Don\'t ask me again" processada.')
            wait_for_page_load(driver)
        except TimeoutException:
            print('Tela "Don\'t ask me again" não apareceu; seguindo adiante.')
    else:
        print('Domínio mudou após o login ({}); pulando "Don\'t ask me again".'.format(current_netloc))

    # Login - "2FA" Screen (opcional)
    wait_for_2fa_if_present(driver)

    # Login - Finish
    wait_for_page_load(driver)

    cookie = driver.get_cookie("SVPNCOOKIE")['value']
    driver.quit()
    return cookie

def wait_for_initial_load_with_refresh(driver, timeout_per_attempt=15, max_refreshes=5):
    print(f'Esperando página carregar (timeout {timeout_per_attempt}s por tentativa, até {max_refreshes} refreshs)...')
    attempts = 0
    while True:
        try:
            WebDriverWait(driver, timeout_per_attempt).until(
                lambda d: d.execute_script('return document.readyState') == 'complete'
            )
            time.sleep(1)
            return True
        except TimeoutException:
            attempts += 1
            if attempts > max_refreshes:
                return False
            print(f'Tempo esgotado. Dando refresh... (tentativa de refresh {attempts}/{max_refreshes})')
            driver.refresh()

def wait_for_2fa_if_present(driver, max_wait=300):
    """
    Aguarda o usuário concluir a verificação 2FA quando a tela estiver presente.
    Detecta títulos: "Approve sign in request" ou "Verify your identity"
    no elemento com id 'idDiv_SAOTCAS_Title'.
    """
    targets = ("approve sign in request", "verify your identity")

    # Tenta detectar rapidamente se a tela de 2FA apareceu
    try:
        title_el = WebDriverWait(driver, 5).until(
            EC.presence_of_element_located((By.ID, "idDiv_SAOTCAS_Title"))
        )
        title_text = (title_el.text or "").strip().lower()
    except TimeoutException:
        print('Tela "2FA" não apareceu; seguindo adiante.')
        return

    if not any(t in title_text for t in targets):
        print('Tela "2FA" não detectada pelo título; seguindo adiante.')
        return

    print(f'Tela "2FA" detectada: "{title_el.text.strip()}". Aguardando usuário concluir...')

    # Aguarda até a tela desaparecer ou o título mudar, por até max_wait segundos
    end_time = time.time() + max_wait
    while time.time() < end_time:
        try:
            els = driver.find_elements(By.ID, "idDiv_SAOTCAS_Title")
            if not els:
                break
            txt = (els[0].text or "").strip().lower()
            if not any(t in txt for t in targets):
                break
        except Exception:
            # Elemento ficou "stale" ou houve mudança de página
            break
        time.sleep(1)

    # Garante que a próxima página esteja carregada
    try:
        wait_for_page_load(driver)
    except TimeoutException:
        pass

def manual_login(driver, host):
    print('Login manual.')
    driver.get(host)
    print("Por favor, faça o login manualmente...")
    while not driver.get_cookie("SVPNCOOKIE"):
        time.sleep(1)
    cookie = driver.get_cookie("SVPNCOOKIE")['value']
    driver.quit()
    return cookie


def run_sudo_command(command):
    command.insert(0, 'sudo')
    return subprocess.run(command, text=True)


def connect_vpn(cookie, host, lan_enabled, server_cert, vpn_slice, verbose=False):
    print('Conectando na vpn.')
    command = [
        'openconnect',
        '--no-dtls',
        '--protocol=fortinet',
        host,
        '--servercert',
        server_cert,
        f'--cookie=SVPNCOOKIE={cookie}'
    ]
    if verbose:
        command.append('-vv')
    if lan_enabled:
        command.extend(['-s', f'vpn-slice {vpn_slice}'])
    run_sudo_command(command)


def keep_sudo_alive():
    print('Mantendo o sudo vivo.')
    while True:
        run_sudo_command(['-v'])
        time.sleep(60)


def check_for_updates():
    print('Verificando atualizações.')
    result = subprocess.run(['git', 'fetch'], capture_output=True, text=True, cwd=SCRIPT_DIR)
    if result.returncode != 0:
        raise Exception("Erro ao verificar atualizações.")
    result = subprocess.run(['git', 'status'], capture_output=True, text=True, cwd=SCRIPT_DIR)
    if 'Your branch is up to date' in result.stdout:
        print('Nenhuma atualização disponível.')
        return False
    else:
        print('Atualizações disponíveis.')
        return True


def upgrade_script():
    print('Atualizando script.')
    result = subprocess.run(['git', 'pull'], capture_output=True, text=True, cwd=SCRIPT_DIR)
    if result.returncode != 0:
        raise Exception("Erro ao atualizar script.")
    print('Script atualizado com sucesso.')


def parse_arguments():
    print('Configurando argumentos.')
    parser = argparse.ArgumentParser(description="Script unificado para conexão VPN.")
    parser.add_argument('-i', '--install', action='store_true', help='Instala os pacotes necessários.')
    parser.add_argument('-o', '--off', action='store_true', help='Conecta ao VPN com LAN desabilitada.')
    parser.add_argument('-m', '--manual', action='store_true',
                        help='Usa a execução manual do script de login. Implica --browser automaticamente')
    parser.add_argument('-b', '--browser', action='store_true', help='Mostra a execução do login SSO no navegador.')
    parser.add_argument('-H', '--host', type=int, choices=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], default=1,
                        help='Define o host VPN para a conexão.')
    parser.add_argument('-s', '--setup', action='store_true', help='Configura o arquivo vpn-config.json.')
    parser.add_argument('-p', '--plain', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('-u', '--update', action='store_true', help='Verifica se há atualização do script.')
    parser.add_argument('-U', '--upgrade', action='store_true', help='Atualiza o script.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Ativa a verbosidade no openconnect.')
    parser.add_argument('-f', '--file', type=str, help='Especifica o arquivo de configuração a ser usado.')
    return parser.parse_args()


def setup_config():
    config = load_config()
    for key, value in config.items():
        if key == 'encrypted-password' or key == 'password' or key == 'salt':
            continue
        change = input(f'Deseja mudar a configuração de "{key}" (atual: {value})? (y/N): ').strip().lower()
        if change == 'y':
            new_value = input(f'Insira o novo valor para "{key}": ').strip()
            config[key] = new_value

    save_config(config)

    change_password = input('Deseja mudar a senha criptografada? (y/N): ').strip().lower()
    if change_password == 'y':
        sudo_password = getpass.getpass("Digite a senha do sudo: ")
        plain_password = getpass.getpass("Digite a nova senha que deseja criptografar: ")
        salt = os.urandom(16)
        encrypted_password = encrypt_password(plain_password, sudo_password, salt)
        config['encrypted-password'] = encrypted_password
        config['salt'] = base64.b64encode(salt).decode()
        save_config(config)
        print("Nova senha criptografada salva no arquivo de configuração.")


def check_sudo_password(sudo_password):
    command = ['sudo', '-S', 'echo', 'password correct']
    result = subprocess.run(command, input=sudo_password + '\n', stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True)
    if 'password correct' in result.stdout:
        return True
    else:
        return False


def main():
    print('Iniciando vpn.')
    args = parse_arguments()

    global CONFIG_FILE
    if args.file:
        CONFIG_FILE = args.file
    else:
        CONFIG_FILE = os.path.join(SCRIPT_DIR, 'vpn-config.json')

    if args.install:
        install_packages()
        return

    if args.setup:
        setup_config()
        return

    if args.update:
        if check_for_updates():
            print("Há atualizações disponíveis. Use o parâmetro `--upgrade` para atualizar o script ou execute `git pull` no repositorio.")
        else:
            print("O script está atualizado.")
        return

    if args.upgrade:
        upgrade_script()
        return

    config = load_config()

    if args.plain:
        print("Aviso: Usar a senha em texto claro não é recomendável. Depreciado. Marcado para remoção.")
        password = config['password']
    else:
        sudo_password = getpass.getpass("Digite a senha do sudo: ")

        if not check_sudo_password(sudo_password):
            print("Senha do sudo incorreta.")
            return

        encrypted_password = config['encrypted-password']
        salt = base64.b64decode(config['salt'])
        password = decrypt_password(encrypted_password, sudo_password, salt)

    host = config['host_mapping'][str(args.host)]
    username = config['username']
    server_cert = config['server_cert']
    vpn_slice = config['vpn_slice']
    lan_enabled = not args.off

    if check_for_updates():
        print("Há atualizações disponíveis. Por favor, atualize o script para a versão mais recente.")
        input("Pressione Enter para continuar...")

    driver = configure_driver(args)
    hostHttps = f"https://{host}/"

    print('Host selecionado: ' + host)

    if args.manual:
        cookie = manual_login(driver, hostHttps)
    else:
        cookie = automate_login(driver, hostHttps, username, password)

    connect_vpn(cookie, host, lan_enabled, server_cert, vpn_slice, verbose=args.verbose)
    # keep_sudo_alive()


if __name__ == "__main__":
    main()

"""
PsCJWAkA8S4
"""
