from bs4 import BeautifulSoup
import hashlib
import json
import os
import pandas as pd
import pathlib
from pathlib import Path
import requests
from slugify import slugify
import time

from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urljoin
from urllib.parse import urlparse

from time import sleep

from internetarchive import get_session, get_item


MAX_RECURSIVE = 10
SLEEP_PAUSE = 0.75
MAX_CHECKS = 6

WAYBACK_EXISTS_URL = 'https://archive.org/wayback/available'
WAYBACK_SAVE_URL = 'https://web.archive.org/save/'

CLIENT_HEADERS = {
    'User-Agent': 'Sucho.org Data Rescue Python Wayback Backup API-Client'
}


# Get the root_path for this jupyter notebook repo.
REPO_PATH = os.path.dirname(os.path.abspath(os.getcwd()))

FILE_CACHE_DIR = f'{REPO_PATH}/files'
URL_TRACKING_FILE =f'{REPO_PATH}/url_tracking/url_tracking_{TRACK_SUFFIX}.json'

CSV_COLS = [
    'file',
    'exists',
    'seed_url',	
    'updated',
    'url',
    'check_count',
    'wayback_ok',
    'archive_ok',
    'internet_archive_item_id',
]
SKIP_DOMAINS = [
    'google.com',
    'twitter.com',
    'facebook.com',
    'pinterest.com',
    'youtube.com',
    'stumbleupon.com',
    'digg.com',
]

DSPACE_URL_CHECK = 'simple-search?'
DSPACE_ALLOWED_PARAMS = [
    'rpp',
    '31300',
    'query',
    'sort_by',
    'order',
    'etal',
]

def read_secrets(repo_path=REPO_PATH):
    secrets_file = os.path.join(repo_path, 'secrets.json')
    if not os.path.exists(secrets_file):
        raise print(f'Cannot find : {secrets_file}')
    with open(secrets_file, 'r') as openfile:
        # Reading from json file
        secrets_dict = json.load(secrets_file)
    return secrets_dict


SECRETS_DICT = read_secrets()


def start_ia_session():
    """ starts an internet archive session """
    config = dict(
        s3=dict(
            acccess=SECRETS_DICT.get('INTERNET_ARCHIVE_ACCESS_KEY'),
            secret=SECRETS_DICT.get('INTERNET_ARCHIVE_SECRET_KEY'),
        )
    )
    s = get_session(config=config, debug=True)
    s.access_key = SECRETS_DICT.get('INTERNET_ARCHIVE_ACCESS_KEY')
    s.secret_key = SECRETS_DICT.get('INTERNET_ARCHIVE_SECRET_KEY')
    return s


def url_param_clean(raw_url, url_check=DSPACE_URL_CHECK, allowed_params=DSPACE_ALLOWED_PARAMS):
    # simple-search?query=&sort_by=score&order=desc&rpp=100&etal=0&start=31300
    if not url_check in raw_url:
        return raw_url
    parsed_url = urlparse(raw_url)
    new_url = parsed_url.scheme + parsed_url.netloc + parsed_url.path
    new_params = {}
    for param in allowed_params:
        if not parse_qs(parsed_url.query).get(param):
            continue
        new_params[param] = parse_qs(parsed_url.query)[param][0]
    if len(new_params) < 1:
        # This actually didn't fit our expected model so, skip out
        return raw_url
    new_url += '?' + urlencode(new_params)
    print(f'Cleaned parameters from {raw_url} to {new_url}')
    return new_url

def clean_url(raw_url):
    raw_url = str(raw_url)
    raw_url = raw_url.strip() # remove whitespaces, etc.
    raw_url = raw_url.replace('\\r', '')  # common URL problem
    raw_url = raw_url.replace('\\n', '')  # common URL problem
    if '#' in raw_url:
        # skip fragment identifiers in URLs
        url_ex = raw_url.split('#')
        raw_url = url_ex[0]
    rem_chars = ['\\', '"', "'"]
    for ch in rem_chars:
        raw_url = raw_url.replace(ch, '')
    return raw_url


def url_tracking_dict_to_csv(url_tracking_file=URL_TRACKING_FILE, key='url', file_url=None, headers_to_cols=False):
    url_tracking_dict = get_url_tracking_dict(url_tracking_file=url_tracking_file)
    rows = []
    for key_url_file, url_meta in url_tracking_dict.items():
        row_dict = {k:v for k,v in url_meta.items()}
        if key == 'url':
            row_dict['url'] = key_url_file
            if not key_url_file.startswith('http'):
                continue
        else:
            row_dict['file'] = key_url_file
            if file_url:
                row_dict['url'] = f'{file_url}{key_url_file}'
        if headers_to_cols and url_meta.get('headers'):
            for k,v in url_meta.get('headers').items():
                row_dict[f'http_resp_header__{k}'] = v
        rows.append(row_dict)
    df = pd.DataFrame(data=rows)
    csv_file = url_tracking_file.replace('.json', '.csv')
    act_cols = [c for c in CSV_COLS if c in df.columns]
    if headers_to_cols:
        header_cols = [c for c in df.columns.tolist() if c.startswith('http_resp_header__')]
        act_cols += header_cols
    if key == 'file':
        df.sort_values(by=['file'], inplace=True)
    df[act_cols].to_csv(csv_file, index=False)


def url_to_ia_item_id(url):
    hash_obj = hashlib.sha1()
    hash_obj.update(url.encode('utf-8'))
    hash_val = hash_obj.hexdigest()
    return f'sucho-id-{hash_val}'


def url_to_ia_key(url):
    hash_obj = hashlib.sha1()
    hash_obj.update(url.encode('utf-8'))
    hash_val = hash_obj.hexdigest()
    extension = pathlib.Path(url).suffix
    if len(extension) > 4:
        extension = ''
    return f'sucho-key-{hash_val}{extension}'


def get_url_tracking_dict(url_tracking_file=URL_TRACKING_FILE):
    if not os.path.exists(url_tracking_file):
        url_tracking_dict = {}
    else:
        with open(url_tracking_file, 'r') as openfile:
            # Reading from json file
            url_tracking_dict = json.load(openfile)
    return url_tracking_dict


def update_url_tracking_dict(
    url, 
    seed_url,
    wayback_ok=None, 
    archive_ok=None,
    has_links=None,
    scrape_ok=None,
    headers=None,
    header_location=None,
    url_tracking_dict=None,
    check_count=None, 
    url_tracking_file=URL_TRACKING_FILE
):
    if not url_tracking_dict:
        url_tracking_dict = get_url_tracking_dict(url_tracking_file=url_tracking_file)
    url_dict = url_tracking_dict.get(url, {})
    url_dict['seed_url'] = seed_url
    if not url_dict.get('check_count') and check_count is None:
        url_dict['check_count'] = 0
    if check_count is None:
        url_dict['check_count'] += 1
    else:
        url_dict['check_count'] = check_count
    if scrape_ok is not None:
        url_dict['scrape_ok'] = scrape_ok
    if has_links is not None:
        url_dict['has_links'] = has_links
    if wayback_ok is not None:
        url_dict['wayback_ok'] = wayback_ok
    if archive_ok is not None:
        url_dict['archive_ok'] = archive_ok
    if headers is not None:
        url_dict['headers'] = headers
    if header_location is not None:
        url_dict['header_location'] = header_location
    if archive_ok:
        url_dict['internet_archive_item_id'] = url_to_ia_item_id(url)
    url_dict['updated'] = time.strftime('%Y-%m-%dT%H:%M:%S') + 'Z'
    url_tracking_dict[url] = url_dict
    with open(url_tracking_file, "w") as outfile:
        json.dump(url_tracking_dict, outfile, indent=4)
    return url_tracking_dict


def wayback_exists(url, session=None, delay_before_request=0.25, client_headers=CLIENT_HEADERS,):
    """Checks if there's a Wayback save of a URL"""
    if delay_before_request > 0:
        # default to sleep BEFORE a request is sent, to
        # give the remote service a break.
        sleep(delay_before_request)
    if not session:
        session = start_ia_session()
    json = None
    try:
        r = session.get(WAYBACK_EXISTS_URL,
            params={'url': url},
            timeout=240,
            headers=client_headers
        )
        r.raise_for_status()
        json = r.json()
    except:
        json = None
    if not json:
        return False
    if len(json.get('archived_snapshots', {})) > 0:
        return True
    return False


def wayback_archive_url(url, session=None, delay_before_request=SLEEP_PAUSE, client_headers=CLIENT_HEADERS, try_again=True):
    """ Archive the URL with the Wayback Machine """
    if delay_before_request > 0:
        # default to sleep BEFORE a request is sent, to
        # give the remote service a break.
        sleep(delay_before_request)
    if not session:
        session = start_ia_session()
    ok = None
    try:
        # now execute the request to the internet archive API
        # s_url = self.wb_save_url + quote(url, safe='')
        s_url = WAYBACK_SAVE_URL + url
        r = session.post(s_url,
            params={
                'capture_all': 1,
                'capture_outlinks': 1,
                'delay_wb_availability': 1,
                'skip_first_archive': 1,
            },
            timeout=240,
            headers=client_headers
        )
        r.raise_for_status()
        ok = True
    except:
        ok = False
    if not ok and not try_again:
        print(f'Wayback failed to archive {url}')
    if not ok and try_again:
        ok = wayback_archive_url(
            url=url, 
            session=None, 
            delay_before_request=(delay_before_request * 2),
            client_headers=client_headers,
            try_again=False
        )
    return ok


def make_filename_from_url(url):
    slug_url = slugify(url)
    if len(slug_url) > 150:
        hash_obj = hashlib.sha1()
        hash_obj.update(url.encode('utf-8'))
        hash_val = hash_obj.hexdigest()
        slug_url = f'url-hash-{hash_val}'
    extension = pathlib.Path(url).suffix
    if '?' in extension:
        extension = ''
    if len(extension) > 4:
        extension = ''
    slug_url = f'{slug_url}{extension}'
    return slug_url



def file_cache_url(url, slug_url=None, cache_dir=FILE_CACHE_DIR, delay_before_request=SLEEP_PAUSE,):
    if not slug_url:
        slug_url = make_filename_from_url(url)
    cache_file_path = os.path.join(cache_dir, slug_url)
    if os.path.exists(cache_file_path):
        return cache_file_path
    if delay_before_request > 0:
        # default to sleep BEFORE a request is sent, to
        # give the remote service a break.
        sleep(delay_before_request)
    print(f'Download {url} to save to {cache_file_path}')
    try:
        r = requests.get(url, stream=True)
        r.raise_for_status()
    except:
        print(f'FAILED {url}, not saved.')
        return None
    # Save it locally
    with open(cache_file_path, 'wb') as f:
        for chunk in r.iter_content(1024):
            f.write(chunk)
    f.close()
    return cache_file_path


def prepend_zeros(num, digit_length=7):
    """ prepends zeros if too short """
    # example: 0008914
    num = str(num)
    while len(num) < digit_length:
        num = '0' + num
    return num


def pdf_cache_file(file_index_num, check_again=False, exist_files=[]):
    file_num = prepend_zeros(file_index_num)
    file_name = f'UKR{file_num}.pdf'
    if file_name in exist_files:
        print(f'Prior run saved {file_name}')
        return None
    tracking_file = f'{REPO_PATH}/url_tracking/urk_pdf_tracking.json'
    cache_dir = f'{REPO_PATH}/ukr_pdf_files'
    tracking_dict = get_url_tracking_dict(tracking_file)
    file_dict = tracking_dict.get(file_name, {})
    if not check_again and file_dict.get('exists') == False:
        # We know this doesn't exist
        print(f'Determined not to exist {file_name}')
        return None
    file_url = f'http://irbis-nbuv.gov.ua/E_LIB/PDF/{file_name}'
    cache_file_path = os.path.join(cache_dir, file_name)
    if os.path.exists(cache_file_path):
        # We already have the file.
        print(f'Already cached {file_url}')
        return None
    headers, _ = get_header_and_location(file_url)
    if not headers:
        file_dict['exists'] = False
        print(f'Does NOT exist {file_url}')
    else:
        print(f'Attempt to cache {file_url}')
        file_dict['exists'] = True
        file_dict['headers'] = headers
        act_cache_file_path = file_cache_url(url=file_url, slug_url=file_name, cache_dir=cache_dir)
        if not act_cache_file_path:
            file_dict['download_ok'] = False
        else:
            file_dict['download_ok'] = True
    file_dict['updated'] = time.strftime('%Y-%m-%dT%H:%M:%S') + 'Z'
    tracking_dict[file_name] = file_dict
    with open(tracking_file, "w") as outfile:
        json.dump(tracking_dict, outfile, indent=4)


def pdf_cache(max_num=8914, check_again=False, exist_files=[]):
    i = max_num
    while i >= 1:
        pdf_cache_file(
            file_index_num=i, 
            check_again=check_again,
            exist_files=exist_files,
        )
        i -= 1


def nlu_image_url_get(page_url, url, url_contains='pic=files/'):
    """Special function to find full image files from a URL"""
    if not url:
        return None
    if not url_contains in url:
        return None
    parsed_url = urlparse(url)
    captured_value = parse_qs(parsed_url.query)['pic'][0]
    full_url = consolidate_clean_url(page_url, captured_value)
    return full_url


def make_metadata_dict(url, is_image=None, image_ref_url=None, seed_url=SEED_URL):
    """ makes the metadata dict for the current item """
    metadata = {'collection': 'opencontext'}
    metadata['uri'] = url
    metadata['title'] = f'Archive of: {url}'
    metadata['partof'] = f'Part of data rescue scrape of: {seed_url}'
    metadata['publisher'] = 'Saving Ukrainian Cultural Heritage Online (SUCHO.org)'
    metadata['description'] = (
        f'From: {UK_COLLECTION_NAME} \n'
        f'{EN_COLLECTION} \n'
        f'Data rescue copy of {url} scrapped from {seed_url} \n'
    )
    image_ext_list = ['.jpg', '.jpeg', '.png', '.tif', '.tiff', '.gif']
    if is_image is None:
        l_url = url.lower()
        for ext in image_ext_list:
            if l_url.endswith(ext):
                is_image = True
                break
    if is_image:
        metadata['mediatype'] = 'image'
    if is_image and image_ref_url:
        metadata['description'] += f'Image linked from {image_ref_url}'
    return metadata


def wayback_or_archive_url(
    url, 
    is_image=None, 
    image_ref_url=None, 
    seed_url=SEED_URL, 
    session=None, 
    url_tracking_dict=None,
    wayback_only=False,
):
    if not url_tracking_dict:
        url_tracking_dict = get_url_tracking_dict()
    if url_tracking_dict.get(url):
        if url_tracking_dict[url].get('wayback_ok') or url_tracking_dict[url].get('archive_ok'):
            # This URL is already archived
            return url_tracking_dict
        if url_tracking_dict[url].get('check_count', 0) > MAX_CHECKS:
            # This URL has already been checked too many times
            return url_tracking_dict
    if not session:
        session = start_ia_session()
    wayback_ok = None
    archive_ok = None
    if wayback_exists(url, session=session):
        wayback_ok = True
    if not wayback_ok:
        # It's not in the wayback machines, so try to put it there
        wayback_ok = wayback_archive_url(url=url, session=session)
    if wayback_only:
        # We're only archiving with the Wayback Machine
        print(f'Wayback ONLY archive result {wayback_ok}; for {url}')
        return url_tracking_dict
    if not wayback_ok:
        # The wayback machine won't archive it, so cache and load it to our collection
        cache_file_path = file_cache_url(url)
        if cache_file_path:
            metadata = make_metadata_dict(
                url=url, 
                is_image=is_image,
                image_ref_url=image_ref_url,
                seed_url=seed_url
            )
            item_id = url_to_ia_item_id(url)
            item = get_item(
                item_id,
                archive_session=session,
                debug=True
            )
        try:
            r = item.upload_file(
                cache_file_path,
                key=url_to_ia_key(url),
                metadata=metadata
            )
            if r.status_code == requests.codes.ok:
                archive_ok = True
            else:
                archive_ok = False
        except:
            archive_ok = False    
    # Track the outcomes
    print(f'wayback_ok: {wayback_ok}; archive_ok: {archive_ok};  url: {url}')
    print('---------------------------------------------------------------')
    url_tracking_dict = update_url_tracking_dict(
        url=url, 
        seed_url=seed_url, 
        wayback_ok=wayback_ok, 
        archive_ok=archive_ok, 
        url_tracking_dict=url_tracking_dict,
    )
    return url_tracking_dict


def read_file_if_exists(url, cache_dir=FILE_CACHE_DIR,):
    slug_url = make_filename_from_url(url)
    cache_file_path = os.path.join(cache_dir, slug_url)
    if not os.path.exists(cache_file_path):
        return None
    try:
        with open(cache_file_path, 'r') as file:
            content = file.read()
    except:
        return None
    return content


def consolidate_clean_url(source_url, raw_url):
    raw_url = clean_url(raw_url)
    if raw_url.startswith('http://') or raw_url.startswith('https://'):
        return raw_url
    new_url = urljoin(source_url, raw_url)
    return clean_url(new_url)


def get_header_and_location(url, delay_before_request=SLEEP_PAUSE,):
    headers = None
    headers_location = None
    try:
        r = requests.head(url)
        r.raise_for_status()
        if r.headers:
            headers = {k:v for k,v in r.headers.items() if k is not None and v is not None}
    except:
        headers = None
    if isinstance(headers, dict):
        headers_location = headers.get('location', headers.get('Location'))
    if headers_location:
        headers_location = consolidate_clean_url(url, headers_location)
    return headers, headers_location


def get_urls_from_url(
    url,
    allow_paths=ALLOW_PATHS,
    seed_url=SEED_URL, 
    session=None, 
    url_tracking_dict=None, 
    delay_before_request=SLEEP_PAUSE, 
    client_headers=CLIENT_HEADERS,
    rescrape=False,
    cache_dir=FILE_CACHE_DIR,
):
    url_tracking_dict = get_url_tracking_dict()
    check_count = 0
    if url_tracking_dict.get(url):
        if url_tracking_dict[url].get('scrape_ok') and not rescrape:
            # This URL is already scraped
            print(f'Already scrapped {url}')
            return []
        check_count = url_tracking_dict[url].get('check_count', 0)
        if check_count > MAX_CHECKS:
            # We've already checked this URL too many times.
            print(f'Exceeded max check count {check_count} for {url}')
            return []
    parsed_url = urlparse(url)
    path_ok = True
    for skip_domain in SKIP_DOMAINS:
        if skip_domain in parsed_url.netloc:
            print(f'Not allowed domain {SKIP_DOMAINS} for {url}')
            update_url_tracking_dict(url=url, seed_url=seed_url)
            return []
    if allow_paths:
        path_ok = False
        for path in allow_paths:
            if path in url:
                path_ok = True
    if not path_ok:
        # This URL is outside our paths of interest
        print(f'Not allowed domain outside {allow_paths} {url}')
        update_url_tracking_dict(url=url, seed_url=seed_url)
        return []
    skip_extensions = [
        # common files we don't want to download
        '.pdf',
        '.ppt',
        '.doc',
        '.xls',
        '.jpg',
        '.jpeg',
        '.png',
        '.tif',
        '.tiff',
        '.gif',
        '.zip',
        '.tgz',
        '.exe',
        '.EXE'
    ]
    l_url = url.lower()
    for skip_ex in skip_extensions:
        if l_url.endswith(skip_ex):
            url_tracking_dict = wayback_or_archive_url(
                url=url, 
                seed_url=seed_url, 
                session=session, 
                url_tracking_dict=url_tracking_dict,
            )
            print(f'Has non html extension {url}')
            update_url_tracking_dict(url=url, seed_url=seed_url)
            return []
    urls = []
    img_src_urls = []
    headers = None
    headers_location = None
    html = read_file_if_exists(url, cache_dir=cache_dir)
    if not html:
        # Get the headers and any redirect location
        headers, headers_location = get_header_and_location(
            url, 
            delay_before_request=delay_before_request
        )
        if delay_before_request > 0:
            # default to sleep BEFORE a request is sent, to
            # give the remote service a break.
            sleep(delay_before_request)
        try:
            r = requests.get(
                url,
                timeout=240,
                headers=client_headers
            )
            r.raise_for_status()
            html = str(r.content)
        except:
            html = None
    if not isinstance(html, str):
        scrape_ok = False
    else:
        scrape_ok = True
        soup = None
        try:
            soup = BeautifulSoup(html, 'lxml')
        except:
            soup = None
            scrape_ok = False
    if not scrape_ok:
        url_tracking_dict = update_url_tracking_dict(
            url=url, 
            seed_url=seed_url, 
            scrape_ok=False,
            url_tracking_dict=url_tracking_dict,
        )
        print(f'HTML cannot be scrapped {url}')
        update_url_tracking_dict(url=url, seed_url=seed_url)
        return []  
    for link in soup.find_all('a'):
        do_raw_url = True
        raw_url = link.get('href')
        raw_url = clean_url(raw_url)
        for skip_domain in SKIP_DOMAINS:
            if skip_domain in raw_url:
                # skip it, it's for a social media site
                do_raw_url = False
        if not do_raw_url:
            continue
        new_url = consolidate_clean_url(url, raw_url)
        if new_url not in urls and new_url != url:
            urls.append(new_url)
        file_url = nlu_image_url_get(url, new_url)
        if file_url and file_url not in urls:
            print(f'{url} has a file URL {file_url}')
            urls.append(file_url)
    for iframe in soup.find_all('iframe'):
        do_src_url = True
        raw_url = iframe.get('src')
        if not isinstance(raw_url, str):
            continue
        raw_url = clean_url(raw_url)
        for skip_domain in SKIP_DOMAINS:
            if skip_domain in raw_url:
                # skip it, it's for a social media site
                do_src_url = False
        if not do_src_url:
            continue
        src_url = consolidate_clean_url(url, raw_url)
        if src_url not in urls:
            urls.append(src_url)
        _, src_headers_location = get_header_and_location(
            url, 
            delay_before_request=delay_before_request
        )
        if src_headers_location and src_headers_location not in urls:
            urls.append(src_headers_location)
    print(f'Searching {url} for image URLs...')
    for img in soup.find_all('img'):
        do_src_url = True
        raw_url = img.get('src')
        if not isinstance(raw_url, str):
            continue
        raw_url = clean_url(raw_url)
        for skip_domain in SKIP_DOMAINS:
            if skip_domain in raw_url:
                # skip it, it's for a social media site
                do_src_url = False
        if not do_src_url:
            continue
        src_url = consolidate_clean_url(url, raw_url)
        if src_url not in img_src_urls:
            img_src_urls.append(src_url)
        _, src_headers_location = get_header_and_location(
            url, 
            delay_before_request=delay_before_request
        )
        if src_headers_location and src_headers_location not in img_src_urls:
            img_src_urls.append(src_headers_location)
        file_url = nlu_image_url_get(url, src_url)
        if file_url and file_url not in img_src_urls:
            print(f'{url} has a file URL {file_url}')
            img_src_urls.append(file_url)
    if len(img_src_urls):
        if not session:
            session = start_ia_session()
        print(f'Attempt to archive {len(img_src_urls)} images from {url}')
        for img_url in img_src_urls:
            url_tracking_dict = wayback_or_archive_url(
                url=img_url, 
                is_image=True, 
                image_ref_url=url, 
                seed_url=seed_url, 
                session=session, 
                url_tracking_dict=url_tracking_dict,
            )
    if headers_location:
        if headers_location not in urls:
            print(f'Found location header {url} to {headers_location}')
            urls.append(headers_location)
    # Save the tracking for this resource
    url_tracking_dict = update_url_tracking_dict(
        url=url, 
        seed_url=seed_url, 
        scrape_ok=True,
        has_links=((len(urls) + len(img_src_urls)) > 0),
        headers=headers,
        header_location=headers_location,
        check_count=(check_count+1),
        url_tracking_dict=url_tracking_dict,
    )
    wayback_or_archive_url(
        url=url, 
        seed_url=SEED_URL, 
        session=session, 
        wayback_only=True,
    )
    # Now cache this url
    file_cache_url(url=url)
    return urls


def recursive_crawl_archive(url, seed_url=SEED_URL, session=None, depth=0, rescrape=False, checked_urls=None):
    if not checked_urls:
        checked_urls = []
    depth += 1
    if depth > MAX_RECURSIVE:
        return checked_urls
    if url in checked_urls:
        return checked_urls
    if not session:
        session = start_ia_session()
    url_tracking_dict = get_url_tracking_dict()
    url_dict = url_tracking_dict.get(url, {})
    url_check_count = url_dict.get('check_count', 0)
    if url_check_count > MAX_CHECKS:
        # We've already checked this URL too many times.
        return checked_urls
    print(f'Crawl, scape, archive {url} (Depth: {depth}). Total checked {len(checked_urls)}')
    raw_urls = get_urls_from_url(
        url=url,
        seed_url=seed_url, 
        session= session, 
        rescrape=rescrape,
    )
    urls = []
    if not URL_CRAWL_LIMITS:
        urls = raw_urls
    else:
        # Check to make sure we don't have URLs excluded by our crawler limits
        urls = []
        for raw_url in raw_urls:
            url_ok = True
            for url_part, allow_list in URL_CRAWL_LIMITS.items():
                if not url_part in raw_url:
                    continue
                url_ok = False
                for allow_url in allow_list:
                    if allow_url in checked_urls:
                        # We've already seen this URL.
                        continue
                    if allow_url in urls:
                        continue
                    # Allow on of the allowed URLs for this otherwise
                    # excluded crawl.
                    urls.append(allow_url)
            if url_ok:
                urls.append(raw_url)
    url_tracking_dict = get_url_tracking_dict()
    url_dict = url_tracking_dict.get(url, {})
    new_url_check_count = url_dict.get('check_count', 0)
    if  new_url_check_count <= url_check_count:
        print(f'Update {url} check_count from {new_url_check_count} to {url_check_count}')
        url_check_count += 1
        update_url_tracking_dict(
            url, 
            seed_url,
            check_count=url_check_count,
        )
    checked_urls.append(url)
    for act_url in urls:
        if act_url in checked_urls:
            continue
        checked_urls = recursive_crawl_archive(
            url=act_url, 
            seed_url=seed_url, 
            session=session, 
            depth=depth,
            rescrape=rescrape,
            checked_urls=checked_urls,
        )
        if act_url not in checked_urls:
            checked_urls.append(act_url)
    return checked_urls


def update_crawl_archive(seed_url=SEED_URL, extra_urls=[]):
    session = start_ia_session()
    url_tracking_dict = get_url_tracking_dict()
    urls = list(url_tracking_dict.keys())
    urls += extra_urls
    if seed_url not in urls:
        urls.append(seed_url)
    checked_urls = []
    for url in urls:
        if url in checked_urls:
            continue
        checked_urls = recursive_crawl_archive(
            url=url,
            session=session,
            rescrape=True,
            checked_urls=checked_urls,
        )
        if not url in checked_urls:
            checked_urls.append(url)
    url_tracking_dict_to_csv()