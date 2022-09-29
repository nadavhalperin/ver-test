import pyminizip
import pickle
import os
import io
from google_auth_oauthlib.flow import Flow, InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from google.auth.transport.requests import Request
import hashlib

CLIENT_SECRET_FILE = 'credentials.json'
API_NAME = 'drive'
API_VERSION = 'v3'
SCOPES = ['https://www.googleapis.com/auth/drive', 'https://www.googleapis.com/auth/admin.reports.audit.readonly']


def create_service():
    """
    create a connection to the service, using nedded scope and users creds
    :return: None
    """
    print(CLIENT_SECRET_FILE, API_NAME, API_VERSION, SCOPES, sep='-')
    cred = None

    pickle_file = f'token_{API_NAME}_{API_VERSION}.pickle'

    if os.path.exists(pickle_file):
        with open(pickle_file, 'rb') as token:
            cred = pickle.load(token)

    if not cred or not cred.valid:
        if cred and cred.expired and cred.refresh_token:
            cred.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_FILE, SCOPES)
            cred = flow.run_local_server()

        with open(pickle_file, 'wb') as token:
            pickle.dump(cred, token)

    try:
        service = build(API_NAME, API_VERSION, credentials=cred)
        print(API_NAME, 'service created successfully')
        return service
    except Exception as e:
        print('Unable to connect.')
        print(e)
        return None


def download_file(file_id, file_name):
    """
    download a file from drive
    :param file_id: id of the drive file
    :param file_name: name to file after download
    :return: None
    """
    service = create_service()

    request = service.files().get_media(fileId=file_id)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fd=fh, request=request)
    done = False

    while not done:
        status, done = downloader.next_chunk()

    fh.seek(0)

    with open(file_name, 'wb') as file:
        file.write(fh.read())
        file.close()


def upload_file(file):
    """
    uploads a given file to google drive
    :param file: file to upload
    :return: uploaded file id
    """
    service = create_service()

    file_type = 'application/zip'

    file_metadata = {
        'name': file,
    }

    media = MediaFileUpload(file, mimetype=file_type)

    drive_file = service.files().create(
        body=file_metadata,
        media_body=media,
        fields='id'
    ).execute()
    return drive_file.get('id')


def create_pass_zip(src_file, password, new_name):
    """
    creates a password protested zip from a file, saves it as upload_zip.zip
    :param src_file: file to compress
    :param password: files password
    :param new_name: name to save file as
    :return: None
    """
    pyminizip.compress(src_file, None, new_name, password, 5)


def extract_zip(file_name, password):
    """
    extraxt a zip
    :param file_name: zip to extract
    :param password: password for zip
    :return: None
    """
    pyminizip.uncompress(file_name, password, '.', 0)


def calc_sha256(file_name):
    """
    calc extracted file sha256
    :param file_name: extracted file
    :return: sha256 value of file
    """
    sha256_hash = hashlib.sha256()
    with open(file_name, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        print('sha256 of file: ', sha256_hash.hexdigest())
        return sha256_hash.hexdigest()


def create_sha_zip(unprotected_zip, sha_value):
    """
    create unprotected zip for sha file
    :param unprotected_zip: name of unprotected zip file
    :param sha_value: sha256 value of file
    :return: None
    """
    with open('tmp_sha', 'w') as f:
        f.write(sha_value)
        f.close()
    pyminizip.compress('temp_sha', None, unprotected_zip, None, 5)
    os.remove('tmp_sha')


def main():
    password = 'asdf'
    file_to_zip = 'top_secret_file.txt'
    download_file_name = 'downloaded.zip'
    protected_zip = 'new.zip'
    unprotected_zip = 'unprotected_zip.zip'

    create_pass_zip(file_to_zip, password, protected_zip)
    file_id = upload_file(protected_zip)
    download_file(file_id, download_file_name)
    extract_zip(download_file_name, password)
    sha_value = calc_sha256(file_to_zip)
    create_sha_zip(unprotected_zip, sha_value)
    upload_file(unprotected_zip)


if __name__ == '__main__':
    main()
