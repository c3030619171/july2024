import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

def download_instagram_reel(driver, reel_url):
    try:
        driver.get('https://saveinsta.app/')
        input_field = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, 's_input'))
        )
        input_field.send_keys(reel_url)
        download_button = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, 'button[type="button"]'))
        )
        download_button.click()

        try:
            close_ad_button = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.ID, 'closeModalBtn'))
            )
            close_ad_button.click()
        except Exception as e:
            print("No ad found to close")

        intermediate_download_button = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, 'a.abutton.is-success.is-fullwidth.btn-premium.mt-3'))
        )
        intermediate_download_button.click()

        final_download_button = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.XPATH, "//span[text()='Download Video']"))
        )
        final_download_button.click()

        time.sleep(10)
    except Exception as e:
        print(f"Error downloading {reel_url}: {e}")

def main():
    options = Options()
    options.set_preference("browser.download.folderList", 2)
    options.set_preference("browser.download.manager.showWhenStarting", False)
    options.set_preference("browser.download.dir", "D:\\DCIM\\download_videos\\downloaded_videos")
    options.set_preference("browser.helperApps.neverAsk.saveToDisk", "video/mp4")
    driver_path = 'd:\\downloads\\softwares\\geckodriver.exe'
    service = Service(driver_path)
    driver = webdriver.Firefox(service=service, options=options)
    try:
        with open('instagram_reel_links.txt', 'r') as file:
            urls = file.readlines()
        for url in urls:
            url = url.strip()
            if url:
                print(f"Processing URL: {url}")
                download_instagram_reel(driver, url)
    finally:
        driver.quit()

if __name__ == "__main__":
    main()
