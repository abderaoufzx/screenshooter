#!/usr/bin/env python3

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import re
import os
import sys
import subprocess
import datetime
import time
import signal
import multiprocessing
import itertools
import shlex
import logging
import errno
import argparse
import base64
import io
import json
from tqdm import tqdm

# Python 2 and 3 compatibility
if sys.version_info < (3, 0):
    os_getcwd = os.getcwdu
    izip = itertools.izip
else:
    os_getcwd = os.getcwd
    izip = zip

# Script version
VERSION = '2.95'

# Global variable to track the multiprocessing pool
POOL = None

# Options definition
parser = argparse.ArgumentParser()

main_grp = parser.add_argument_group('Main parameters')
main_grp.add_argument('URL', help='Single URL target given as a positional argument', nargs='?')
main_grp.add_argument('-i', '--input-file', help='<INPUT_FILE> text file containing the target list. Ex: list.txt')
main_grp.add_argument('--subfinder-input', help='<SUBFINDER_INPUT> (optional): JSON output file from subfinder', type=str)
main_grp.add_argument('-o', '--output-directory', help='<OUTPUT_DIRECTORY> (optional): screenshots output directory (default \'./screenshots/\')')
main_grp.add_argument('-w', '--workers', help='<WORKERS> (optional): number of parallel execution workers (default 4)', default=4)
main_grp.add_argument('-v', '--verbosity', help='<VERBOSITY> (optional): verbosity level, repeat to increase { -v INFO, -vv DEBUG } (default ERROR)', action='count', default=0)
main_grp.add_argument('--no-error-file', help='<NO_ERROR_FILE> (optional): do not write a file with the list of failed URLs (default false)', action='store_true', default=False)
main_grp.add_argument('-z', '--single-output-file', help='<SINGLE_OUTPUT_FILE> (optional): name of a file for single output of all inputs. Ex: test.png')
main_grp.add_argument('--retries', help='<RETRIES> (optional): number of retries for failed screenshots (default 2)', type=int, default=2)

proc_grp = parser.add_argument_group('Input processing parameters')
proc_grp.add_argument('-p', '--port', help='<PORT> (optional): use the specified port for each target. Ex: -p 80')
proc_grp.add_argument('-s', '--ssl', help='<SSL> (optional): enforce SSL/TLS for every connection', action='store_true', default=False)
proc_grp.add_argument('-m', '--multiprotocol', help='<MULTIPROTOCOL> (optional): perform screenshots over HTTP and HTTPS', action='store_true', default=False)

renderer_grp = parser.add_argument_group('Screenshot renderer parameters')
renderer_grp.add_argument('-r', '--renderer', help='<RENDERER> (optional): renderer to use among \'phantomjs\', \'chrome\', \'chromium\', \'edgechromium\', \'firefox\' (default \'chromium\')', choices=['phantomjs', 'chrome', 'chromium', 'edgechromium', 'firefox'], type=str.lower, default='chromium')
renderer_grp.add_argument('--renderer-binary', help='<RENDERER_BINARY> (optional): path to the renderer executable if not in $PATH')
renderer_grp.add_argument('--no-xserver', help='<NO_X_SERVER> (optional): use xvfb-run if no X server (default: detect DISPLAY env)', action='store_true', default=('DISPLAY' not in os.environ) and ('win32' not in sys.platform.lower()))

image_grp = parser.add_argument_group('Screenshot image parameters')
image_grp.add_argument('--window-size', help='<WINDOW_SIZE> (optional): width and height of the screen capture (default \'1200,800\')', default='1200,800')
image_grp.add_argument('-f', '--format', help='<FORMAT> (optional, phantomjs only): output image format, "pdf", "png", "jpg", "jpeg", "bmp", "ppm" (default \'png\')', choices=['pdf', 'png', 'jpg', 'jpeg', 'bmp', 'ppm'], type=str.lower, default='png')
image_grp.add_argument('-q', '--quality', help='<QUALITY> (optional, phantomjs only): output image quality, 0-100 (default 75)', metavar="[0-100]", choices=range(0, 101), type=int, default=75)
image_grp.add_argument('--ajax-max-timeouts', help='<AJAX_MAX_TIMEOUTS> (optional, phantomjs only): AJAX and max URL timeout in ms (default \'1400,1800\')', default='1400,1800')
image_grp.add_argument('--crop', help='<CROP> (optional, phantomjs only): rectangle <t,l,w,h> to crop (default to WINDOW_SIZE: \'0,0,w,h\')')
image_grp.add_argument('--custom-js', help='<CUSTOM_JS> (optional, phantomjs only): path to JavaScript file to execute before screenshot')

image_grp = parser.add_argument_group('Screenshot label parameters')
image_grp.add_argument('-l', '--label', help='<LABEL> (optional): create a screenshot with the target URL (requires imagemagick)', action='store_true', default=False)
image_grp.add_argument('--label-size', help='<LABEL_SIZE> (optional): font size for the label (default 60)', type=int, default=60)
image_grp.add_argument('--label-bg-color', help='<LABEL_BACKGROUND_COLOR> (optional): label imagemagick background color (default NavajoWhite)', default="NavajoWhite")
image_grp.add_argument('--imagemagick-binary', help='<LABEL_BINARY> (optional): path to imagemagick binary if not in $PATH')

http_grp = parser.add_argument_group('HTTP parameters')
http_grp.add_argument('-c', '--cookie', help='<COOKIE_STRING> (optional): cookie string. Ex: -c "JSESSIONID=1234; YOLO=SWAG"')
http_grp.add_argument('-a', '--header', help='<HEADER> (optional): custom header. Ex: -a "Host: localhost"', action='append')
http_grp.add_argument('-u', '--http-username', help='<HTTP_USERNAME> (optional): username for HTTP Basic Authentication')
http_grp.add_argument('-b', '--http-password', help='<HTTP_PASSWORD> (optional): password for HTTP Basic Authentication')

conn_grp = parser.add_argument_group('Connection parameters')
conn_grp.add_argument('-P', '--proxy', help='<PROXY> (optional): specify a proxy. Ex: -P http://proxy.company.com:8080')
conn_grp.add_argument('-A', '--proxy-auth', help='<PROXY_AUTH> (optional): proxy authentication. Ex: -A user:password')
conn_grp.add_argument('-T', '--proxy-type', help='<PROXY_TYPE> (optional): proxy type, "http" (default), "none", "socks5"', default='http')
conn_grp.add_argument('-t', '--timeout', help='<TIMEOUT> (optional): renderer timeout in seconds (default 30)', default=30)

# Renderer binaries
env = os.environ.copy()
env['OPENSSL_CONF'] = '/dev/null'

PHANTOMJS_BIN = 'phantomjs'
CHROME_BIN = 'google-chrome'
CHROMIUM_BIN = 'chromium'
FIREFOX_BIN = 'firefox'
XVFB_BIN = "xvfb-run -a"
IMAGEMAGICK_BIN = "convert"

SCREENSHOOTER_JS = os.path.abspath(os.path.join(os.path.dirname(__file__), './screenshooter.js'))
SCREENSHOTS_DIRECTORY = os.path.abspath(os.path.join(os_getcwd(), './screenshots/'))
FAILED_SCREENSHOTS_FILE = os.path.abspath(os.path.join(os_getcwd(), './screenshots_failed.txt'))

# Logger definition
LOGLEVELS = {0: 'ERROR', 1: 'INFO', 2: 'DEBUG'}
logger_output = logging.StreamHandler(sys.stdout)
logger_output.setFormatter(logging.Formatter('[%(levelname)s][%(name)s] %(message)s'))

logger_gen = logging.getLogger("General")
logger_gen.addHandler(logger_output)

# Macros
SHELL_EXECUTION_OK = 0
SHELL_EXECUTION_ERROR = -1
PHANTOMJS_HTTP_AUTH_ERROR_CODE = 2

CONTEXT_RENDERER = 'renderer'
CONTEXT_IMAGEMAGICK = 'imagemagick'

# Patterns
p_ipv4_elementary = r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})'
p_domain = r'[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]+'
p_port = r'\d{0,5}'
p_resource = r'(?:/(?P<res>.*))?'

full_uri_domain = re.compile(r'^(?P<protocol>http(?:|s))://(?P<host>%s|%s)(?::(?P<port>%s))?%s$' % (p_domain, p_ipv4_elementary, p_port, p_resource))
fqdn_and_port = re.compile(r'^(?P<host>%s):(?P<port>%s)%s$' % (p_domain, p_port, p_resource))
fqdn_only = re.compile(r'^(?P<host>%s)%s$' % (p_domain, p_resource))
ipv4_and_port = re.compile(r'^(?P<host>%s):(?P<port>%s)%s' % (p_ipv4_elementary, p_port, p_resource))
ipv4_only = re.compile(r'^(?P<host>%s)%s$' % (p_ipv4_elementary, p_resource))
entry_from_csv = re.compile(r'^(?P<host>%s|%s)\s+(?P<port>\d+)$' % (p_domain, p_ipv4_elementary))

# Handful functions
def is_windows():
    return "win32" in sys.platform.lower()

def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def kill_em_all(sig, frame):
    global POOL
    logger_gen.info('Received signal %s, cleaning up and exiting...', 'SIGINT' if sig == signal.SIGINT else 'SIGTERM')
    
    if POOL:
        logger_gen.debug('Terminating multiprocessing pool...')
        POOL.terminate()
        POOL.join()
        POOL = None
    
    if not is_windows():
        try:
            pgid = os.getpgid(os.getpid())
            os.killpg(pgid, signal.SIGKILL)
        except Exception as e:
            logger_gen.error(f'Failed to kill process group: {e}')
    
    sys.exit(1)

def shell_exec(url, command, options, context):
    logger_url = logging.getLogger(url)
    logger_url.setLevel(options.log_level)
    
    timeout = int(options.timeout)
    start = datetime.datetime.now()
    
    def group_subprocesses():
        if options.no_xserver and not is_windows():
            os.setsid()
    
    def close_subfds(s):
        s.stdout.close()
        s.stderr.close()
    
    try:
        if is_windows():
            p = subprocess.Popen(shlex.split(command, posix=not is_windows()), shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        else:
            p = subprocess.Popen(shlex.split(command, posix=not is_windows()), shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=group_subprocesses, env=env)
        
        stdout, stderr = p.communicate(timeout=timeout)
        retval = p.returncode
        
        if retval != SHELL_EXECUTION_OK:
            if retval == PHANTOMJS_HTTP_AUTH_ERROR_CODE:
                logger_url.error("HTTP Authentication requested, use -u and -b options")
            else:
                logger_url.error(f"Shell command PID {p.pid} returned error code: {retval}")
                logger_url.error(f"STDERR: {stderr.decode('utf-8', errors='ignore')}")
                logger_url.error("Screenshot failed\n")
            return SHELL_EXECUTION_ERROR
        
        logger_url.debug(f"Shell command PID {p.pid} ended normally")
        logger_url.info("Screenshot OK\n")
        return SHELL_EXECUTION_OK
    
    except subprocess.TimeoutExpired:
        logger_url.error(f"Shell command PID {p.pid} reached timeout, killing it")
        logger_url.error("Screenshot failed\n")
        close_subfds(p)
        if is_windows():
            p.send_signal(signal.SIGTERM)
        else:
            if options.no_xserver:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            else:
                p.send_signal(signal.SIGKILL)
        return SHELL_EXECUTION_ERROR
    except OSError as e:
        if e.errno == errno.ENOENT:
            if context == CONTEXT_RENDERER:
                if options.no_xserver and not is_windows():
                    logger_url.error('No X server found and xvfb-run binary not found, install xvfb')
                else:
                    logger_url.error(f'{context} binary not found in PATH')
            elif context == CONTEXT_IMAGEMAGICK:
                logger_url.error(f'{context} binary not found in PATH')
            return SHELL_EXECUTION_ERROR
    except Exception as err:
        logger_url.error(f'Unknown error: {err}, exiting')
        return SHELL_EXECUTION_ERROR

def filter_bad_filename_chars_and_length(filename):
    filename = filename.rstrip('/').replace('://', '_')[:129]
    return re.sub(r'[^\w\-_\. ]', '_', filename)

def extract_all_matched_named_groups(regex, match):
    result = {}
    for name, id in regex.groupindex.items():
        matched_value = match.group(name)
        if matched_value is not None:
            result[name] = matched_value
    return result

def entry_format_validator(line):
    tab = {
        'full_uri_domain': full_uri_domain,
        'fqdn_only': fqdn_only,
        'fqdn_and_port': fqdn_and_port,
        'ipv4_and_port': ipv4_and_port,
        'ipv4_only': ipv4_only,
        'entry_from_csv': entry_from_csv
    }
    
    for name, regex in tab.items():
        validator = regex.match(line)
        if validator:
            return extract_all_matched_named_groups(regex, validator)

def parse_targets(options):
    target_list = set()
    
    if options.subfinder_input:
        with open(options.subfinder_input, 'r') as f:
            subfinder_data = json.load(f)
            for entry in subfinder_data.get('results', []):
                host = entry.get('host')
                if host:
                    protocol = 'https' if options.ssl else 'http'
                    port = options.port or (443 if protocol == 'https' else 80)
                    final_uri = f'{protocol}://{host}:{port}'
                    target_list.add(final_uri)
                    logger_gen.info(f"Added {host} as {final_uri}")
    
    elif options.input_file:
        with open(options.input_file, 'rb') as fd_input:
            try:
                lines = [l.decode('utf-8').strip() for l in fd_input.readlines()]
            except UnicodeDecodeError:
                logger_gen.error('Input file must be UTF-8 encoded')
                sys.exit(1)
    else:
        lines = [options.URL]
    
    for index, line in enumerate(lines, start=1):
        matches = entry_format_validator(line)
        if not matches or 'host' not in matches:
            logger_gen.warning(f"Line {index} '{line}' not recognized as valid input")
            continue
        
        host = matches['host']
        protocol = 'https' if options.ssl else matches.get('protocol', 'http')
        port = int(options.port or matches.get('port', 443 if protocol == 'https' else 80))
        res = '/' + matches.get('res', '')
        
        if options.multiprotocol:
            for proto, default_port in [('http', 80), ('https', 443)]:
                final_port = port if 'port' in matches else default_port
                final_uri = f'{proto}://{host}:{final_port}{res}'
                target_list.add(final_uri)
                logger_gen.info(f"'{line}' formatted as '{final_uri}'")
        else:
            final_uri = f'{protocol}://{host}:{port}{res}'
            target_list.add(final_uri)
            logger_gen.info(f"'{line}' formatted as '{final_uri}'")
    
    return list(target_list)

def craft_bin_path(options, context=CONTEXT_RENDERER):
    final_bin = []
    
    if context == CONTEXT_RENDERER:
        if options.no_xserver and not is_windows():
            final_bin.append(XVFB_BIN)
        
        if options.renderer_binary:
            final_bin.append(options.renderer_binary)
        else:
            if options.renderer == 'phantomjs':
                final_bin.append(PHANTOMJS_BIN)
            elif options.renderer == 'chrome':
                final_bin.append(CHROME_BIN)
            elif options.renderer == 'chromium':
                final_bin.append(CHROMIUM_BIN)
            elif options.renderer == 'firefox':
                final_bin.append(FIREFOX_BIN)
    
    elif context == CONTEXT_IMAGEMAGICK:
        final_bin.append(options.imagemagick_binary or IMAGEMAGICK_BIN)
    
    return " ".join(final_bin)

def craft_arg(param):
    if is_windows():
        return f'{param}'
    return f'"{param}"'

def launch_cmd(logger, url, cmd_parameters, options, context):
    cmd = " ".join(cmd_parameters)
    logger.debug(f"Executing: '{cmd}'\n")
    return shell_exec(url, cmd, options, context)

def craft_output_filename_and_format(url, options):
    output_format = options.format if options.renderer == 'phantomjs' else 'png'
    
    if options.single_output_file:
        if options.single_output_file.lower().endswith(f'.{output_format}'):
            output_filename = os.path.abspath(filter_bad_filename_chars_and_length(options.single_output_file))
        else:
            output_filename = os.path.abspath(filter_bad_filename_chars_and_length(f'{options.single_output_file}.{output_format}'))
    else:
        output_filename = os.path.join(options.output_directory, f'{filter_bad_filename_chars_and_length(url)}.{output_format}')
    
    return output_format, output_filename

def craft_cmd(url_and_options):
    global logger_output, SCREENSHOOTER_JS, SHELL_EXECUTION_OK, SHELL_EXECUTION_ERROR
    
    url, options = url_and_options
    logger_url = logging.getLogger(url)
    logger_url.addHandler(logger_output)
    logger_url.setLevel(options.log_level)
    
    output_format, output_filename = craft_output_filename_and_format(url, options)
    execution_retval = SHELL_EXECUTION_ERROR
    
    for attempt in range(options.retries + 1):
        if execution_retval == SHELL_EXECUTION_OK:
            break
        logger_url.info(f"Attempt {attempt + 1}/{options.retries + 1} for {url}")
        
        if options.renderer == 'phantomjs':
            cmd_parameters = [
                craft_bin_path(options),
                '--ignore-ssl-errors=true',
                '--ssl-protocol=any',
                '--ssl-ciphers=ALL',
                f'{craft_arg(SCREENSHOOTER_JS)} url_capture={url} output_file={craft_arg(output_filename)}',
                f'width={options.window_size.split(",")[0]}',
                f'height={options.window_size.split(",")[1]}',
                f'format={options.format}',
                f'quality={options.quality}',
                f'ajaxtimeout={options.ajax_max_timeouts.split(",")[0]}',
                f'maxtimeout={options.ajax_max_timeouts.split(",")[1]}'
            ]
            if options.proxy:
                cmd_parameters.append(f'--proxy={options.proxy}')
            if options.proxy_auth:
                cmd_parameters.append(f'--proxy-auth={options.proxy_auth}')
            if options.proxy_type:
                cmd_parameters.append(f'--proxy-type={options.proxy_type}')
            if options.cookie:
                cmd_parameters.append(f'header="Cookie: {options.cookie.rstrip(";")}"')
            if options.http_username:
                auth = base64.b64encode(f'{options.http_username}:{options.http_password or ""}'.encode()).decode()
                cmd_parameters.append(f'header="Authorization: Basic {auth}"')
            if options.crop:
                width, height = options.window_size.split(',')
                crop_rectangle = options.crop.replace('w', width).replace('h', height)
                cmd_parameters.append(f'crop="{crop_rectangle}"')
            if options.header:
                for header in options.header:
                    cmd_parameters.append(f'header="{header.rstrip(";")}"')
            if options.custom_js and os.path.exists(options.custom_js):
                cmd_parameters.append(f'customjs={craft_arg(os.path.abspath(options.custom_js))}')
        
        elif options.renderer in ['chrome', 'chromium', 'edgechromium']:
            cmd_parameters = [
                'node',
                os.path.abspath(os.path.join(os.path.dirname(__file__), 'screenshooter_puppeteer.js')),
                f'url_capture={url.rstrip("/")}',
                f'output_file={os.path.abspath(output_filename)}',
                f'window_size={options.window_size}',
                f'timeout={options.timeout}'
            ]
            if options.http_username:
                cmd_parameters.append(f'http_username={options.http_username}')
            if options.http_password:
                cmd_parameters.append(f'http_password={options.http_password}')
            if options.header:
                for header in options.header:
                    cmd_parameters.append(f'header={header.rstrip(";")}')
            if options.renderer_binary:
                env['RENDERER_BINARY'] = os.path.abspath(options.renderer_binary)
        
        elif options.renderer == 'firefox':
            cmd_parameters = [
                craft_bin_path(options),
                '--new-instance',
                f'--screenshot={craft_arg(output_filename)}',
                f'--window-size={options.window_size}',
                craft_arg(url)
            ]
        
        execution_retval = launch_cmd(logger_url, url, cmd_parameters, options, CONTEXT_RENDERER)
        if execution_retval == SHELL_EXECUTION_ERROR and attempt < options.retries:
            logger_url.warning(f"Attempt {attempt + 1} failed, retrying...")
            time.sleep(2)
    
    if options.label and execution_retval == SHELL_EXECUTION_OK:
        output_filename_label = os.path.join(options.output_directory, f'{filter_bad_filename_chars_and_length(url)}_with_label.{output_format}')
        cmd_parameters = [
            craft_bin_path(options, CONTEXT_IMAGEMAGICK),
            craft_arg(output_filename),
            f'-pointsize {options.label_size}',
            '-gravity Center',
            f'-background {options.label_bg_color}',
            f"label:'{url}'",
            '+swap',
            f'-append {craft_arg(output_filename_label)}'
        ]
        execution_retval_label = launch_cmd(logger_url, url, cmd_parameters, options, CONTEXT_IMAGEMAGICK)
    
    return execution_retval, url

def take_screenshot(url_list, options):
    global POOL
    screenshot_number = len(url_list)
    print(f"[+] {screenshot_number} URLs to be screenshot")
    
    max_workers = min(int(options.workers), multiprocessing.cpu_count())
    POOL = multiprocessing.Pool(processes=max_workers, initializer=init_worker)
    
    taken_screenshots = []
    with tqdm(total=screenshot_number, desc="Screenshots", unit="URL") as pbar:
        for result in POOL.imap(func=craft_cmd, iterable=izip(url_list, itertools.repeat(options))):
            taken_screenshots.append(result)
            pbar.update(1)
    
    POOL.close()
    POOL.join()
    POOL = None
    
    results = []
    for retval, url in taken_screenshots:
        if retval == SHELL_EXECUTION_OK:
            output_format, output_filename = craft_output_filename_and_format(url, options)
            metadata_file = output_filename.replace(f'.{output_format}', '.json')
            if os.path.exists(metadata_file):
                with open(metadata_file, 'r') as f:
                    try:
                        results.append(json.load(f))
                    except Exception as e:
                        logger_gen.warning(f"Could not read metadata from {metadata_file}: {e}")
                os.remove(metadata_file)
    
    screenshots_error_url = [url for retval, url in taken_screenshots if retval == SHELL_EXECUTION_ERROR]
    screenshots_error = sum(retval == SHELL_EXECUTION_ERROR for retval, url in taken_screenshots)
    screenshots_ok = screenshot_number - screenshots_error
    
    print(f"[+] {screenshots_ok} URLs screenshot successfully")
    print(f"[+] {screenshots_error} error(s)")
    
    if screenshots_error and not options.no_error_file:
        with io.open(FAILED_SCREENSHOTS_FILE, 'w', newline='\n') as fd_out:
            for url in screenshots_error_url:
                fd_out.write(url + '\n')
                print(f"    {url}")
    elif screenshots_error:
        for url in screenshots_error_url:
            print(f"    {url}")
    
    results_file = os.path.join(options.output_directory, "results.json")
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"[+] Report metadata written to {results_file}")
    
    return results_file

def run_generate_report(results_file):
    """Run generate_report.py to create the HTML report."""
    generate_report_script = "generate_report.py"
    output_html = "report.html"
    
    logger_gen.info("Generating HTML report...")
    
    if not os.path.isfile(generate_report_script):
        logger_gen.error(f"{generate_report_script} not found in the current directory")
        return
    
    try:
        result = subprocess.run(
            [sys.executable, generate_report_script, results_file, "-o", output_html],
            check=True,
            capture_output=True,
            text=True
        )
        logger_gen.info(f"HTML report generated: {output_html}")
        logger_gen.debug(result.stdout.strip())
    except subprocess.CalledProcessError as e:
        logger_gen.error(f"Failed to generate HTML report: {e.stderr}")
    except FileNotFoundError:
        logger_gen.error(f"Python executable or {generate_report_script} not found")

def main():
    global VERSION, SCREENSHOTS_DIRECTORY, LOGLEVELS
    signal.signal(signal.SIGINT, kill_em_all)
    signal.signal(signal.SIGTERM, kill_em_all)
    
    print(f'screenshooter.py version {VERSION}\n')
    
    options = parser.parse_args()
    
    try:
        options.log_level = LOGLEVELS[options.verbosity]
        logger_gen.setLevel(options.log_level)
    except:
        parser.error("Please specify a valid log level")
    
    if not any([options.input_file, options.URL, options.subfinder_input]):
        parser.error('Specify an input file, a URL, or a Subfinder JSON file')
    
    if sum(1 for x in [options.input_file, options.URL, options.subfinder_input] if x) > 1:
        parser.error('Specify only one of input file, URL, or Subfinder JSON')
    
    if options.single_output_file:
        options.workers = 1
    
    options.output_directory = os.path.join(os_getcwd(), options.output_directory or SCREENSHOTS_DIRECTORY)
    
    logger_gen.debug(f"Options: {options}\n")
    if not os.path.exists(options.output_directory):
        logger_gen.info(f"'{options.output_directory}' does not exist, creating it")
        os.makedirs(options.output_directory)
    
    if options.crop and len(options.crop.split(',')) != 4:
        parser.error('Specify a valid crop rectangle (t,l,w,h)')
    
    url_list = parse_targets(options)
    results_file = take_screenshot(url_list, options)
    
    # Automatically run generate_report.py
    run_generate_report(results_file)

if __name__ == "__main__":
    main()