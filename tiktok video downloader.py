import time
import random
import string
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

def download_tiktok_video(driver, video_url):
    try:
        driver.get('https://ssstik.io/')
        input_field = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, 'main_page_text'))
        )
        input_field.send_keys(video_url)
        download_button = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.ID, 'submit'))
        )
        download_button.click()
        without_watermark_button = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, 'a.without_watermark'))
        )
        without_watermark_button.click()
        time.sleep(10)
    except Exception as e:
        print(f"Error downloading {video_url}: {e}")

def main():
    options = Options()
    options.set_preference("browser.download.folderList", 2)
    options.set_preference("browser.download.manager.showWhenStarting", False)
    options.set_preference("browser.download.dir", "D:\DCIM\download_videos\downloaded_videos")
    options.set_preference("browser.helperApps.neverAsk.saveToDisk", "video/mp4")
    driver_path = 'D:\downloads\softwares\geckodriver-v0.34.0-win64\geckodriver.exe'
    service = Service(driver_path)
    driver = webdriver.Firefox(service=service, options=options)
    try:
        with open('tiktok_links.txt', 'r') as file:
            urls = file.readlines()
        for url in urls:
            url = url.strip()
            if url:
                print(f"Processing URL: {url}")
                download_tiktok_video(driver, url)
    finally:
        driver.quit()

if __name__ == "__main__":
    main()
