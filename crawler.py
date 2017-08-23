#!/usr/bin/env python
# -*- coding: UTF-8 -*-
from glob import glob
import os
import sys
import json
from time import sleep
from contextlib import contextmanager

from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.chrome.options import Options

import top500
from logger import logger
from utils import save_json
import config


base_url = "chrome-extension://mcgekeccgjgcmhnhbabplanchdogjcnh/"
background_url = base_url + "_generated_background_page.html"
storages = [ 'action_map', 'snitch_map', 'dnt_hashes', 'settings_map' ]


@contextmanager
def xvfb_manager():
    wants_xvfb = bool(config.ENABLE_XVFB)
    if wants_xvfb:
        from xvfbwrapper import Xvfb

        vdisplay = Xvfb(width=1280, height=720)
        vdisplay.start()
        try:
            yield vdisplay
        finally:
            vdisplay.stop()
    else:
        yield


def get_extension_path():
    path = os.environ.get('EXTENSION_PATH', glob('*.crx'))
    if isinstance(path, list):
        if not path:
            raise ValueError("No extension found. Put a .crx file in "
                             "this directory")
        return path.pop()
    logger.info('Using extension at %s' % path)
    return path


def start_driver():
    opts = Options()
    opts.add_extension(get_extension_path())
    opts.add_experimental_option("prefs", {"profile.block_third_party_cookies": False})
    opts.add_argument('--dns-prefetch-disable')
    return webdriver.Chrome(config.CHROMEDRIVER_PATH, chrome_options=opts)


def dump_data(driver):
    driver.get(background_url)
    data = {}
    for storage in storages:
        script = 'return badger.storage.%s.getItemClones()' % storage
        data[storage] = driver.execute_script(script)

    # it is not ortodox extraxt info in this way, but the script
    # is injected in the page, I was not finding the way to use
    # the privacybadger storage
    pattern = 'MATCHP';
    data['fingerprint'] = {}
    for entry in driver.get_log('browser'):
        if not entry.has_key('source'):
            continue
        if entry['source'] != 'console-api':
            continue

        try:
            i = entry['message'].index(pattern) + len(pattern)
            last = json.loads(entry['message'][i+1:-1].replace('\\', ''))
            if sys.getsizeof(last) >= sys.getsizeof(data['fingerprint']):
                data['fingerprint'] = last
        except ValueError:
            pass

    return data


def timeout_workaround(driver):
    '''
    Selenium has a bug where a tab that raises a timeout exception can't
    recover gracefully. So we kill the tab and make a new one.
    '''
    driver.close()  # kill the broken site
    driver.switch_to_window(driver.window_handles.pop())
    before = set(driver.window_handles)
    driver.execute_script('window.open()')
    driver.switch_to_window((set(driver.window_handles) ^ before).pop())
    return driver


def crawl(timeout):
    logger.info('starting new crawl with timeout %d n_urls %d' % (timeout, len(top500.urls)))
    with xvfb_manager():
        driver = start_driver()
        driver.set_page_load_timeout(timeout)
        driver.set_script_timeout(timeout)

        for url in top500.urls:
            try:
                logger.info('visiting %s' % url)
                driver.get(url)
                sleep(timeout)
            except TimeoutException as e:
                logger.info('timeout on %s ' % url)
                driver = timeout_workaround(driver)
                continue
        data = dump_data(driver)
        driver.quit()
        return data


if __name__ == '__main__':
    out_file = os.environ.get('OUT_FILE', 'results.json')
    secstimeout = os.environ.get('TIMEOUT', '40')
    secstimeout = int(secstimeout)

    if len(sys.argv) > 1:
        print "Received target via command line:", sys.argv[1]
        top500.urls = [ sys.argv[1] ]

    save_json(out_file, crawl(secstimeout))
