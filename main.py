#!/usr/bin/env python3
import os
import sys
import csv
import qrcode
import sqlite3
import zipfile
from pathlib import Path
from elevate import elevate
from PyQt5 import QtWidgets
from PyQt5 import uic
from PIL.ImageQt import ImageQt
from pyotp import random_base32, TOTP
from PyQt5.QtGui import QPixmap, QFont, QBrush, QColor
from functions import rsa_vault_decrypt, aes_decrypt, clipboard_wipe, clipboard_copy, check_rsa
from PyQt5.QtWidgets import QMainWindow, QApplication, QDialog, QFileDialog, QWidget, QMessageBox
from database import create_db, get_user, add_entry, add_user_enc_data, add_user, check_passwd, create_cybervault
from functions import generate_keys, pwn_checker, vault_password, rsa_vault_encrypt, aes_encrypt, generate_password
from functions import get_reg_flag, get_reg_key, user_db_enc, user_db_dec, create_vault_key
from database import get_user_enc_data, check_user, check_vault


# Done
class UI(QMainWindow):
    def __init__(self):
        super(UI, self).__init__()
        uic.loadUi("cybervault.ui", self)
        self.vault_user = User()
        self.new_account.clicked.connect(self.create_account)
        self.import_cybervault.clicked.connect(self.open_vault)
        self.login_to_account.clicked.connect(self.login)
        self.backup_btn.clicked.connect(self.backup_account)

    # Done
    def create_account(self):
        new_account_window = NewUser(self.vault_user)
        widget.addWidget(new_account_window)
        widget.setCurrentIndex(widget.currentIndex()+1)

    # Done
    def login(self):
        login_window = Login(self.vault_user)
        widget.addWidget(login_window)
        widget.setCurrentIndex(widget.currentIndex()+1)

    # Done
    def open_vault(self):
        open_vault_window = OpenCyberVault()
        widget.addWidget(open_vault_window)
        widget.setCurrentIndex(widget.currentIndex()+1)

    # Done
    def backup_account(self):
        account_backup = BRAccount()
        widget.addWidget(account_backup)
        widget.setCurrentIndex(widget.currentIndex()+1)


# Done
class NewUser(QDialog):
    def __init__(self, user):
        super(NewUser, self).__init__()
        uic.loadUi("newaccount.ui", self)
        self.img = None
        self.qr = None
        self.uname = None
        self.home = Path.home()
        self.vault_state = None
        self.qrcode = None
        self.v_passwd = None
        self.user_check = None
        self.vault_passwd = None
        self.vault_account = user
        self.vault_check = None
        self.home = os.path.join(self.home, "Documents")

        # Setting up onscreen options
        self.auth_code_lable.hide()
        self.code_entry.hide()
        self.verify_code_btn.hide()
        self.create_account_button.hide()
        self.code_entry.setEnabled(False)
        self.verify_code_btn.setEnabled(False)
        self.create_account_button.setEnabled(False)
        self.verify_mfa_btn.clicked.connect(self.get_username)
        self.create_account_button.clicked.connect(self.get_info)

        # Setting up key variables
        self.vault = None
        self.s_key = None
        self.pri_key = None
        self.pub_key = None
        self.account = False

    # Done
    def setup_mfa(self):
        self.uname = self.username.text()
        self.s_key = random_base32()
        self.vault_account.s_key = self.s_key
        totp = TOTP(self.s_key)
        auth = totp.provisioning_uri(name=self.uname, issuer_name='CyberVault')

        if self.qrcode is None:
            self.img = qrcode.make(auth)
            self.qr = ImageQt(self.img)
            pix = QPixmap.fromImage(self.qr)
            self.qrcode_label.setPixmap(pix)

            self.auth_code_lable.show()
            self.code_entry.show()
            self.verify_code_btn.show()
            self.code_entry.setEnabled(True)
            self.verify_code_btn.setEnabled(True)
            self.verify_code_btn.clicked.connect(self.verify_mfa)

    # Done
    def verify_mfa(self):
        code = self.code_entry.text()
        self.qrcode = QRCodeGenerator(self.s_key, code)
        self.qrcode.verify()

        if self.qrcode.get_verify():
            self.create_account_button.show()
            self.create_account_button.setEnabled(True)

    # Done
    def get_username(self):
        self.uname = self.username.text()

        self.v_passwd = get_reg_key()
        try:
            user_db_dec('users.db', self.v_passwd)
        except Exception as e:
            pass

        # Check username
        if self.uname:
            self.user_check = check_user(self.uname)
            self.check_username()

    # Done
    def create_account(self):
        userid = None
        self.vault_passwd = vault_password()

        result = create_cybervault(self.uname, self.vault)
        # Create account in database and make password vault with MFA
        if result:
            self.account = True
            userid = add_user(self.uname, self.pub_key, self.vault, self.s_key)
            self.vault_account.userid = userid

        session, nonce, tag, ciphertext = rsa_vault_encrypt(self.pub_key, self.vault_passwd)
        if userid:
            add_user_enc_data(userid, session, nonce, tag, ciphertext)

        if self.account:
            self.open_vault()

    # Done
    def get_info(self):
        self.pri_key, self.pub_key = generate_keys()
        self.vault_account.pri_key = self.pri_key
        self.vault_account.pub_key = self.pub_key
        self.save_key()
        self.get_vault_name()

    # Done
    def save_key(self):
        f_name = QFileDialog.getSaveFileName(self, "Save Key", str(self.home), 'Key File (*.pem)')
        if f_name == ('', ''):
            pass
        else:
            file = f_name[0]
            if os.name == 'posix':
                file = f"{file}.pem"

            with open(file, 'wb') as f:
                f.write(self.pri_key)
                f.write(b'\n')

    # Done
    def get_vault_name(self):
        vault = QFileDialog.getSaveFileName(self, "Save Vault", str(self.home),
                                            'CyberVault Database (*.cvdb)')
        if vault == ('', ''):
            pass
        else:
            self.vault_check = check_vault(vault[0])
            self.check_vault_name(vault[0])

    # Done
    def check_vault_name(self, vault):
        if self.vault_check == 'no':
            self.vault_check = None
            self.set_vault_name(vault)

            return

        elif self.vault_check == 'yes':
            self.vault_check = None
            self.vault_popup()
            return

    # Done
    def set_vault_name(self, vault):
        self.vault = vault
        if os.name == 'posix':
            self.vault = f"{vault}.cvdb"
        self.vault_account.vault = self.vault
        self.create_account()

    # Done
    def open_vault(self):
        passvault = PasswordVault(self.vault, self.uname, self.pri_key, self.vault_account, enc_vault=True)
        widget.addWidget(passvault)
        widget.setCurrentIndex(widget.currentIndex()+1)

    # Done
    def check_username(self):
        if self.user_check == 'no':
            self.user_check = None
            self.setup_mfa()
            return
        elif self.user_check == 'yes':
            self.user_check = None
            self.user_popup()
            return

    # Done
    def user_popup(self):
        msg = QMessageBox()

        msg.setWindowTitle("Username Already Taken")
        msg.setText("That username has already been taken! Please pick a different username.")
        msg.setIcon(QMessageBox.Critical)
        msg.setStandardButtons(QMessageBox.Ok)

        self.username.clear()

        msg.exec_()

    # Done
    def vault_popup(self):
        msg = QMessageBox()

        msg.setWindowTitle("Vault Name Already Taken")
        msg.setText("That vault name has already been taken! Please pick a different name or location.")
        msg.setIcon(QMessageBox.Critical)
        msg.setStandardButtons(QMessageBox.Ok)

        msg.exec_()

        self.get_vault_name()


# Done
class Login(QDialog):
    def __init__(self, user):
        super(Login, self).__init__()
        uic.loadUi("login.ui", self)
        self.temp = None
        self.vault = None
        self.pri_key = None
        self.checked = None
        self.username = None
        self.mfa_check = None
        self.otp_s_key = None
        self.home = Path.home()
        self.vault_account = user
        self.home = os.path.join(self.home, "Documents")

        self.auth_code_lable.hide()
        self.auth_code_entry.hide()
        self.verify_code_btn.hide()

        self.login_btn.clicked.connect(self.login)
        self.load_rsa_button.clicked.connect(self.load_key)

    # Done
    def load_key(self):
        f_name = QFileDialog.getOpenFileName(self, 'Load RSA Key', str(self.home), 'Key File (*.pem)')
        self.rsa_key_entry.setText(f_name[0])
        self.temp = check_rsa(f_name[0])
        self.vault_account.pri_key = f_name[0]

    # Done
    def login(self):
        self.username = self.user_entry.text()
        self.pri_key = self.rsa_key_entry.text()

        if self.username:
            v_passwd = get_reg_key()
            try:
                user_db_dec('users.db', v_passwd)

                user, pub_key, self.vault, self.otp_s_key, userid = get_user(self.username)
                if self.temp == pub_key:
                    self.vault_account.s_key = self.otp_s_key
                    self.vault_account.userid = userid
                    self.vault_account.vault = self.vault
                    self.vault_account.pub_key = pub_key

                    if user:
                        self.login_btn.setEnabled(False)
                        self.auth_code_lable.show()
                        self.auth_code_entry.show()
                        self.verify_code_btn.show()
                        self.verify_code_btn.clicked.connect(self.verify_login)

                    else:
                        pass
                else:
                    # Alert user that the wrong RSA key was loaded.
                    self.show_popup()
            except Exception as e:
                pass
        else:
            pass

    # Done
    def verify_login(self):
        code = self.auth_code_entry.text()
        self.mfa_check = QRCodeGenerator(self.otp_s_key, code)
        self.mfa_check.verify()

        result = self.mfa_check.get_verify()
        if result:
            self.open_vault()

    # Done
    def show_popup(self):
        msg = QMessageBox()

        msg.setWindowTitle("Incorrect RSA Private Key")
        msg.setText("""You did not provide the correct RSA Private Key for this vault! Please use the correct key.""")
        msg.setIcon(QMessageBox.Warning)
        msg.setStandardButtons(QMessageBox.Ok)

        self.rsa_key_entry.clear()
        msg.exec_()

    # Done
    def open_vault(self):
        passvault = PasswordVault(self.vault, self.username, self.pri_key, self.vault_account)
        widget.addWidget(passvault)
        widget.setCurrentIndex(widget.currentIndex()+1)


# Done
class OpenCyberVault(QDialog):
    def __init__(self):
        super(OpenCyberVault, self).__init__()
        uic.loadUi("opencybervault.ui", self)

        self.tag = None
        self.user = None
        self.file = None
        self.path = None
        self.nonce = None
        self.s_key = None
        self.vault = None
        self.save = None
        self.pubkey = None
        self.userid = None
        self.username = None
        self.temp_pub = None
        self.mfa_check = None
        self.ciphertext = None
        self.session_key = None
        self.backup_vault = None
        self.home = Path.home()
        self.start_location = os.getcwd()
        self.home = os.path.join(self.home, "Documents")

        # Setup buttons
        self.open_btn.clicked.connect(self.open_archive)
        self.browse_btn.clicked.connect(self.get_archive)

    # Done
    def load_user(self):
        self.username = self.account_entry.text()
        # Get user info from backup db
        self.user, self.pubkey, self.vault, self.s_key, self.userid = get_user(self.username, backup=True, file_path=self.path.parent)
        self.session_key, self.nonce, self.tag, self.ciphertext = get_user_enc_data(self.userid, backup=True, file_path=self.path.parent)

        # Add recovered user to current db
        v_passwd = get_reg_key()
        try:
            user_db_dec('users.db', v_passwd)
            uid = add_user(self.username, self.pubkey, self.vault, self.s_key)
            add_user_enc_data(uid, self.session_key, self.nonce, self.tag, self.ciphertext)
            os.rename(self.backup_vault, self.vault)
            os.remove(self.file)
            os.remove(os.path.join(self.path.parent, 'backup.db'))
        except Exception:
            sys.exit(1)

    # Done
    def get_archive(self):
        f_name = QFileDialog.getOpenFileName(self, "Open Vault", str(self.home), 'Backup Archive (*.zip)')
        if f_name == ('', ''):
            pass
        else:
            self.file = f_name[0]
            if os.name == 'posix':
                self.file = f"{f_name[0]}.zip"

            self.path = Path(self.file)
            self.backup_entry.setText(self.file)

    # Done
    def open_archive(self):
        try:
            with zipfile.ZipFile(self.file, 'r') as backup_archive:
                archive = Path(self.file)
                os.chdir(archive.parent)
                for name in backup_archive.namelist():
                    x = name.split('.')
                    if x[1] == 'cvdb':
                        self.backup_vault = os.path.join(archive.parent, name)
                backup_archive.extractall()

            os.chdir(self.start_location)

        except AttributeError:
            pass

        self.load_user()

    # Done
    def show_popup(self):
        msg = QMessageBox()

        msg.setWindowTitle("Account Recovery")
        msg.setText("Your account has been successfully recovered!")
        msg.setIcon(QMessageBox.Information)
        msg.setStandardButtons(QMessageBox.Ok)

        msg.buttonClicked.connect(self.popup_button)

        msg.exec_()

    # Done
    def popup_button(self, i):
        v_passwd = get_reg_key()
        if i.text() == 'OK':
            # Clear and hide buttons and entry boxes
            self.open_btn.hide()
            self.backup_entry.clear()
            self.open_btn.setEnabled(False)

            # Clear data from all properties
            self.tag = None
            self.user = None
            self.file = None
            self.path = None
            self.nonce = None
            self.s_key = None
            self.vault = None
            self.save = None
            self.pubkey = None
            self.userid = None
            self.username = None
            self.temp_pub = None
            self.mfa_check = None
            self.ciphertext = None
            self.session_key = None
            user_db_enc('users.db', v_passwd)
            back_to_main()
        else:
            user_db_enc('users.db', v_passwd)
            back_to_main()


# Done
class PasswordGenerator(QWidget):
    def __init__(self, pass_entry):
        super(PasswordGenerator, self).__init__()
        uic.loadUi("passwordgenerator.ui", self)

        self.slide_value = 11
        self.save_pass = pass_entry
        self.pass_to_use = None
        self.upper = self.upper_checkbox.isChecked()
        self.lower = self.lower_checkbox.isChecked()
        self.num = self.num_checkbox.isChecked()
        self.special = self.special_checkbox.isChecked()
        self.pass_len_value.setText(str(self.slide_value))

        self.copy_pass_btn.clicked.connect(self.use_pass)
        self.gen_pass_btn.clicked.connect(self.pass_generator)
        self.num_checkbox.stateChanged.connect(self.num_select)
        self.upper_checkbox.stateChanged.connect(self.upper_select)
        self.lower_checkbox.stateChanged.connect(self.lower_select)
        self.pass_len_slider.valueChanged.connect(self.slide_change)
        self.special_checkbox.stateChanged.connect(self.special_select)

    # Done
    def slide_change(self, value):
        self.pass_len_value.setText(str(value))
        self.slide_value = value

    # Done
    def upper_select(self):
        if self.upper_checkbox.isChecked():
            self.upper = True
        else:
            self.upper = False

    # Done
    def lower_select(self):
        if self.lower_checkbox.isChecked():
            self.lower = True
        else:
            self.lower = False

    # Done
    def num_select(self):
        if self.num_checkbox.isChecked():
            self.num = True
        else:
            self.num = False

    # Done
    def special_select(self):
        if self.special_checkbox.isChecked():
            self.special = True
        else:
            self.special = False

    # Done
    def pass_generator(self):
        self.pass_to_use = generate_password(self.upper, self.lower, self.num, self.special, self.gen_pass_label, self.slide_value)

    # Done
    def use_pass(self):
        self.save_pass.setText(self.pass_to_use)


# Done
class QRCodeGenerator:
    def __init__(self, s_key, code):
        self.s_key = s_key
        self.current = code
        self.verified = None

    # Done
    def verify(self):
        mfa_totp = TOTP(self.s_key)

        if mfa_totp.verify(self.current):
            self.verified = True

    # Done
    def get_verify(self):
        return self.verified


# Done
class PasswordVault(QDialog):
    def __init__(self, vault, username, pri_key, account, enc_vault=False):
        super(PasswordVault, self).__init__()
        uic.loadUi("passwordvault.ui", self)

        # Setup variables needed to run class
        self.passwd = None
        self.web_url = None
        self.username = None
        self.copied_pass = None
        self.entry_name = None
        self.pri_key = pri_key
        self.vault_user = account
        self.vault_locked = True
        self.username = username
        self.pass_checker = None
        self.delete_index = None
        self.vault_unlocked = False
        self.passwd_generator = None
        self.vault_path = Path(vault)
        self.conn = sqlite3.connect(self.vault_path)
        self.cur = self.conn.cursor()

        # Hide all disabled buttons at start
        self.vault_lock(enc_vault)

        # Setup window entry boxes and buttons to be disabled at start
        self.copy_btn.setEnabled(False)
        self.name_entry.setEnabled(False)
        self.user_entry.setEnabled(False)
        self.submit_btn.setEnabled(False)
        self.pass_gen_btn.setEnabled(False)
        self.add_entry_btn.setEnabled(False)
        self.web_url_entry.setEnabled(False)
        self.clear_clip_btn.setEnabled(False)
        self.password_entry.setEnabled(False)
        self.check_pass_btn.setEnabled(False)
        self.lock_vault_btn.setEnabled(False)
        self.enable_checkbox.setEnabled(False)
        self.update_entry_btn.setEnabled(False)
        self.delete_entry_btn.setEnabled(False)

        self.pass_gen_btn.clicked.connect(self.pass_gen)
        self.account_table.clicked.connect(self.copy_pass)
        self.add_entry_btn.clicked.connect(self.add_entry)
        self.delete_entry_btn.clicked.connect(self.delete)
        self.check_pass_btn.clicked.connect(self.check_pass)
        self.unlock_vault_btn.clicked.connect(self.vault_unlock)
        self.enable_checkbox.stateChanged.connect(self.is_checked)
        self.lock_vault_btn.clicked.connect(lambda: self.vault_lock(enc_vault=True))

    # Done
    def vault_unlock(self):
        if self.vault_user.unlock_vault():
            # Enable and Disable lock and unlock buttons plus show/hide
            self.lock_vault_btn.show()
            self.unlock_vault_btn.hide()
            self.lock_vault_btn.setEnabled(True)
            self.unlock_vault_btn.setEnabled(False)
            self.delete_entry_btn.setEnabled(True)

            # Display entry boxes and labels.
            self.copy_btn.show()
            self.url_label.show()
            self.user_label.show()
            self.name_entry.show()
            self.user_entry.show()
            self.entry_label.show()
            self.passwd_label.show()
            self.pass_gen_btn.show()
            self.add_entry_btn.show()
            self.web_url_entry.show()
            self.clear_clip_btn.show()
            self.password_entry.show()
            self.lock_vault_btn.show()
            self.enable_checkbox.show()
            self.update_entry_btn.show()
            self.delete_entry_btn.show()

            self.check_pass_btn.show()
            self.check_pass_btn.setEnabled(True)

            self.enable_checkbox.setEnabled(True)
            self.enable_checkbox.show()

            self.load_table()

    # Done
    def vault_lock(self, enc_vault):
        if enc_vault:
            self.vault_user.lock_vault()

        self.unlock_vault_btn.setEnabled(True)
        self.unlock_vault_btn.show()

        self.lock_vault_btn.setEnabled(False)
        self.lock_vault_btn.hide()

        self.copy_btn.setEnabled(False)
        self.pass_gen_btn.setEnabled(False)
        self.clear_clip_btn.setEnabled(False)

        # Hide entry boxes and labels.
        self.copy_btn.hide()
        self.url_label.hide()
        self.user_label.hide()
        self.name_entry.hide()
        self.user_entry.hide()
        self.submit_btn.hide()
        self.entry_label.hide()
        self.passwd_label.hide()
        self.pass_gen_btn.hide()
        self.add_entry_btn.hide()
        self.web_url_entry.hide()
        self.password_entry.hide()
        self.clear_clip_btn.hide()
        self.enable_checkbox.hide()
        self.update_entry_btn.hide()
        self.delete_entry_btn.hide()

        self.enable_checkbox.hide()
        self.enable_checkbox.setEnabled(False)

        self.check_pass_btn.hide()
        self.check_pass_btn.setEnabled(False)

        self.account_table.clear()

        clipboard_wipe()

    # Done
    def load_table(self):
        self.account_table.clear()
        self.account_table.setColumnCount(5)
        self.account_table.setHorizontalHeaderLabels(['ID', 'Name', 'URL', 'Username', 'Password'])
        self.account_table.setColumnWidth(0, 25)
        self.account_table.setColumnWidth(1, 175)
        self.account_table.setColumnWidth(2, 250)
        self.account_table.setColumnWidth(3, 180)
        self.account_table.setColumnWidth(4, 500)
        delegate = PasswordDelegate(self.account_table)
        self.account_table.setItemDelegate(delegate)

        results = self.cur.execute("SELECT * FROM cybervault")
        table_row = 0
        for row in results:
            self.account_table.setRowCount(table_row + 1)
            self.account_table.setItem(table_row, 0, QtWidgets.QTableWidgetItem(str(row[0])))
            self.account_table.setItem(table_row, 1, QtWidgets.QTableWidgetItem(row[1]))
            self.account_table.setItem(table_row, 2, QtWidgets.QTableWidgetItem(row[2]))
            self.account_table.setItem(table_row, 3, QtWidgets.QTableWidgetItem(row[3]))
            self.account_table.setItem(table_row, 4, QtWidgets.QTableWidgetItem(row[4]))

            table_row += 1

    # Done
    def is_checked(self):
        if self.enable_checkbox.isChecked():
            self.entry_enable()
        else:
            self.entry_disable()

    # Done
    def entry_enable(self):
        self.name_entry.setEnabled(True)
        self.web_url_entry.setEnabled(True)
        self.user_entry.setEnabled(True)
        self.password_entry.setEnabled(True)
        self.submit_btn.setEnabled(True)
        self.add_entry_btn.setEnabled(True)
        self.pass_gen_btn.setEnabled(True)
        self.copy_btn.setEnabled(True)
        self.clear_clip_btn.setEnabled(True)

    # Done
    def entry_disable(self):
        self.name_entry.setEnabled(False)
        self.web_url_entry.setEnabled(False)
        self.user_entry.setEnabled(False)
        self.password_entry.setEnabled(False)
        self.submit_btn.setEnabled(False)
        self.add_entry_btn.setEnabled(False)
        self.pass_gen_btn.setEnabled(False)
        self.copy_btn.setEnabled(False)
        self.clear_clip_btn.setEnabled(False)

    # Done
    def add_entry(self):
        self.entry_name = self.name_entry.text()
        self.web_url = self.web_url_entry.text()
        self.username = self.user_entry.text()
        self.passwd = self.password_entry.text()

        if self.entry_name and self.web_url and self.username and self.passwd:
            self.copied_pass = check_passwd(self.vault_path, self.passwd)
            self.submit_btn.show()
            self.submit_btn.setEnabled(True)
            self.submit_btn.clicked.connect(self.check_entry)

    # Done
    def check_entry(self):
        if self.copied_pass == 'no':
            self.copied_pass = None
            self.submit_entry()
            return
        elif self.copied_pass == 'yes':
            self.copied_pass = None
            self.show_popup()
            return

    # Done
    def submit_entry(self):
        add_entry(self.vault_path, self.entry_name, self.web_url, self.username, self.passwd)

        self.name_entry.clear()
        self.web_url_entry.clear()
        self.user_entry.clear()
        self.password_entry.clear()
        self.submit_btn.hide()
        self.submit_btn.setEnabled(False)
        self.enable_checkbox.setChecked(False)

        self.load_table()

    def delete(self):
        if self.delete_index:
            self.cur.execute("DELETE FROM cybervault WHERE vid=?", (self.delete_index,))
            self.delete_index = None
            self.conn.commit()
            self.load_table()

    # Done
    def copy_pass(self):
        request = self.account_table.currentItem()
        row = self.account_table.currentItem().row()
        self.delete_index = self.account_table.item(row, 0).text()

        if request:
            clipboard_copy(request.text())

    # Done
    def pass_gen(self):
        if self.passwd_generator is None:
            self.passwd_generator = PasswordGenerator(self.password_entry)

        self.passwd_generator.show()

    # Done
    def check_pass(self):
        if not self.pass_checker:
            self.pass_checker = PasswordChecker(self.vault_path)

        self.pass_checker.show()

    # Done
    def show_popup(self):
        msg = QMessageBox()

        msg.setWindowTitle("Password not Unique")
        msg.setText("All passwords entered into the CyberVault need to be unique, please use a different password!")
        msg.setIcon(QMessageBox.Critical)
        msg.setStandardButtons(QMessageBox.Ok)

        self.submit_btn.hide()
        self.password_entry.clear()
        self.submit_btn.setEnabled(False)

        msg.exec_()


# Done
class PasswordDelegate(QtWidgets.QStyledItemDelegate):
    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        if index.column() == 4:
            style = option.widget.style() or QtWidgets.QApplication.style()
            hint = style.styleHint(QtWidgets.QStyle.SH_LineEdit_PasswordCharacter)
            option.text = chr(hint) * len(option.text)


# Done
class PasswordChecker(QDialog):
    def __init__(self, vault):
        super(PasswordChecker, self).__init__()
        uic.loadUi("passwordchecker.ui", self)
        self.found = []
        self.file = None
        self.index_list = []
        self.home = Path.home()
        self.conn = sqlite3.connect(vault)
        self.cur = self.conn.cursor()
        self.pass_check_table.setStyleSheet("background-color: rgb(141, 145, 141);")
        self.pass_check_table.setColumnWidth(0, 325)
        self.pass_check_table.setColumnWidth(1, 325)
        self.pass_check_table.setColumnWidth(2, 365)

        self.load_vault_btn.clicked.connect(self.create_table)
        self.pass_check_table.clicked.connect(self.get_index_list)
        self.export_vault_pass_btn.clicked.connect(self.export_csv)
        self.check_vault_pass_btn.clicked.connect(self.check_vault_passwords)
        self.check_single_pass_btn.clicked.connect(self.check_single_password)

    # Done
    def create_table(self):
        self.pass_check_table.clear()
        db = self.cur.execute("""SELECT * FROM cybervault""")
        table_rows = db.fetchall()
        table_rows = len(table_rows)
        self.pass_check_table.setRowCount(table_rows)

        self.load_vault()

    # Done
    def get_index_list(self):
        self.index_list.append(self.pass_check_table.currentRow())
        self.clean_list()

    # Done
    def clean_list(self):
        temp = []
        for x in self.index_list:
            if x not in temp:
                temp.append(x)

        self.index_list = temp

    # Done
    def load_vault(self):
        self.index_list.clear()
        self.pass_check_table.clear()
        results = self.cur.execute("SELECT * FROM cybervault")
        delegate = PasswordDelegate(self.pass_check_table)
        self.pass_check_table.setItemDelegate(delegate)
        tablerow = 0
        for row in results:
            self.pass_check_table.setItem(tablerow, 0, QtWidgets.QTableWidgetItem(row[1]))
            self.pass_check_table.setItem(tablerow, 1, QtWidgets.QTableWidgetItem(row[3]))
            self.pass_check_table.setItem(tablerow, 2, QtWidgets.QTableWidgetItem(row[4]))

            tablerow += 1

    # Done
    def check_single_password(self):
        password = self.single_pass_entry.text()

        result, num = pwn_checker(password)
        num = int(num)

        if result and num <= 100:
            self.single_pass_result_lable.setText(f"Password '{password}' has been compromised {num} times")
            self.single_pass_result_lable.setStyleSheet("background-color: rgb(255, 255, 0);")
        elif result and num > 100:
            self.single_pass_result_lable.setText(f"Password '{password}' has been compromised {num} times")
            self.single_pass_result_lable.setStyleSheet("background-color: rgb(255, 128, 0);")
        else:
            self.single_pass_result_lable.setText(f"Password '{password}' is safe to use")
            self.single_pass_result_lable.setStyleSheet("background-color: rgb(0, 182, 0);")

    # Done
    def check_vault_passwords(self):
        font = QFont()
        font.setBold(True)

        for idx in self.index_list:
            pass_to_check = self.pass_check_table.item(idx, 2).text()
            result, num = pwn_checker(pass_to_check)
            num = int(num)

            if result and num <= 100:
                brush = QBrush(QColor(255, 255, 0))
                self.found.append(idx)
            elif result and num > 100:
                brush = QBrush(QColor(255, 128, 0))
                self.found.append(idx)
            else:
                brush = QBrush(QColor(0, 182, 0))

            self.pass_check_table.item(idx, 0).setFont(font)
            self.pass_check_table.item(idx, 0).setBackground(brush)
            self.pass_check_table.item(idx, 1).setFont(font)
            self.pass_check_table.item(idx, 1).setBackground(brush)
            self.pass_check_table.item(idx, 2).setFont(font)
            self.pass_check_table.item(idx, 2).setBackground(brush)

    # Done
    def export_csv(self):
        self.save_csv()
        header = ['ID', 'Name', 'Website', 'Username', 'Password']
        with open(self.file, 'w', encoding='UTF8', newline='') as f:
            writer = csv.writer(f)

            # write the header
            writer.writerow(header)
            for idx in self.found:
                idx += 1
                result = self.cur.execute("SELECT * FROM cybervault WHERE vid=?", (idx,))

                for row in result:
                    # write the data
                    writer.writerow(row)

    # Done
    def save_csv(self):
        f_name = QFileDialog.getSaveFileName(self, "Save Found Passwords", str(self.home), 'CSV File (*.csv)')
        if f_name == ('', ''):
            pass
        else:
            self.file = f_name[0]
            if os.name == 'posix':
                self.file = f"{f_name[0]}.zip"


# Done
class BRAccount(QDialog):
    def __init__(self):
        super(BRAccount, self).__init__()
        uic.loadUi("backupaccount.ui", self)

        self.tag = None
        self.user = None
        self.file = None
        self.path = None
        self.nonce = None
        self.s_key = None
        self.vault = None
        self.save = None
        self.pubkey = None
        self.userid = None
        self.username = None
        self.temp_pub = None
        self.mfa_check = None
        self.ciphertext = None
        self.session_key = None
        self.home = Path.home()
        self.private_key = None
        self.start_location = os.getcwd()
        self.home = os.path.join(self.home, "Documents")
        self.connect = None
        self.cursor = None

        # Setup buttons
        self.mfa_verify_btn.clicked.connect(self.mfa)
        self.save_btn.clicked.connect(self.backup_vault)
        self.remove_btn.clicked.connect(self.remove_user)
        self.browse_btn.clicked.connect(self.save_archive)
        self.load_rsa_key_btn.clicked.connect(self.load_rsa)
        self.backup_checkBox.stateChanged.connect(self.backup_is_checked)
        self.remove_checkBox.stateChanged.connect(self.remove_is_checked)

        # Hide and disable buttons that are not needed right away.
        self.save_btn.hide()
        self.remove_btn.hide()
        self.mfa_entry.hide()
        self.mfa_verify_btn.hide()
        self.save_btn.setEnabled(False)
        self.remove_btn.setEnabled(False)
        self.mfa_verify_btn.setEnabled(False)
        self.account_user_entry.setEnabled(False)
        self.backup_entry.setEnabled(False)
        self.load_rsa_key_entry.setEnabled(False)
        self.browse_btn.setEnabled(False)
        self.load_rsa_key_btn.setEnabled(False)

    # Done
    def load_rsa(self):
        f_name = QFileDialog.getOpenFileName(self, 'Load RSA Key', str(self.home), 'Key File (*.pem)')
        self.load_rsa_key_entry.setText(f_name[0])
        self.private_key = self.load_rsa_key_entry.text()
        if self.load_rsa_key_entry.text():
            self.temp_pub = check_rsa(f_name[0])
        self.confirm_user()

    def confirm_user(self):
        v_passwd = get_reg_key()
        try:
            user_db_dec('users.db', v_passwd)
            self.username = self.account_user_entry.text()
            if self.username:
                self.user, self.pubkey, self.vault, self.s_key, self.userid = get_user(self.username)
                if self.temp_pub == self.pubkey:
                    self.mfa_entry.show()
                    self.mfa_verify_btn.show()
                    self.mfa_verify_btn.setEnabled(True)
                else:
                    self.load_rsa_key_entry.clear()
            else:
                pass

        except Exception as e:
            print(f"Error: {e}")

    # Done
    def save_user(self):
        if self.userid:
            self.session_key, self.nonce, self.tag, self.ciphertext = get_user_enc_data(self.userid)
            create_db(backup=True, file_path=self.path.parent)
            uid = add_user(self.username, self.pubkey, self.vault, self.s_key, backup=True, file_path=self.path.parent)
            add_user_enc_data(uid, self.session_key, self.nonce, self.tag, self.ciphertext, backup=True,
                              file_path=self.path.parent)

        else:
            pass

    # Done
    def mfa(self):
        code = self.mfa_entry.text()
        if code:
            self.mfa_check = QRCodeGenerator(self.s_key, code)
            self.mfa_check.verify()

        result = self.mfa_check.get_verify()
        if result:
            self.save_btn.show()
            self.remove_btn.show()

    # Done
    def backup_is_checked(self):
        # Check if user wants to backup account
        if self.backup_checkBox.isChecked():
            self.save_btn.setEnabled(True)
            self.remove_checkBox.setChecked(False)
            self.remove_btn.setEnabled(False)
            self.account_user_entry.setEnabled(True)
            self.backup_entry.setEnabled(True)
            self.load_rsa_key_entry.setEnabled(True)
            self.browse_btn.setEnabled(True)
            self.load_rsa_key_btn.setEnabled(True)
            self.browse_btn.show()
            self.backup_entry.show()

    def remove_is_checked(self):
        # Check if user wants to remove account
        if self.remove_checkBox.isChecked():
            self.remove_btn.setEnabled(True)
            self.save_btn.setEnabled(False)
            self.backup_checkBox.setChecked(False)
            self.account_user_entry.setEnabled(True)
            self.load_rsa_key_entry.setEnabled(True)
            self.browse_btn.hide()
            self.backup_entry.hide()
            self.load_rsa_key_btn.setEnabled(True)

    # Done
    def save_archive(self):
        f_name = QFileDialog.getSaveFileName(self, "Save Vault", str(self.home), 'Backup Archive (*.zip)')
        if f_name == ('', ''):
            pass
        else:
            self.file = f_name[0]
            if os.name == 'posix':
                self.file = f"{f_name[0]}.zip"

            self.path = Path(self.file)
            self.backup_entry.setText(self.file)

    # Done
    def backup_vault(self):
        self.save_user()
        backup_db = os.path.join(self.path.parent, 'backup.db')
        with zipfile.ZipFile(self.file, 'w') as backup_archive:
            vault_path = Path(self.vault)
            path = vault_path.parent
            os.chdir(path)
            file = os.path.basename(self.vault)
            backup_archive.write(file)
            os.chdir(self.path.parent)
            file2 = os.path.basename(backup_db)
            backup_archive.write(file2)

        os.remove(backup_db)
        os.remove(vault_path)
        os.chdir(self.start_location)
        self.temp_pub = None
        self.show_popup()

    def remove_user(self):
        connect = sqlite3.connect('users.db')
        cursor = connect.cursor()
        cursor.execute("""DELETE FROM data WHERE userid=?""", (self.userid,))
        connect.commit()
        cursor.execute("""DELETE FROM users WHERE uuid=?""", (self.userid,))
        connect.commit()
        try:
            path = Path(self.vault)
            os.remove(path)
        except TypeError and FileNotFoundError:
            pass
        self.remove_popup()
        self.temp_pub = None

    # Done
    def show_popup(self):
        msg = QMessageBox()

        msg.setWindowTitle("Account Backed up")
        msg.setText("""Your account has been successfully backed up! Please keep it somewhere safe and never store
it in the same location as your private key!""")
        msg.setIcon(QMessageBox.Information)
        msg.setStandardButtons(QMessageBox.Ok)

        msg.buttonClicked.connect(self.popup_button)

        msg.exec_()

    # Done
    def popup_button(self, i):
        if i.text() == 'OK':
            # Clear and hide buttons and entry boxes
            self.save_btn.hide()
            self.mfa_entry.hide()
            self.mfa_entry.clear()
            self.backup_entry.clear()
            self.mfa_verify_btn.hide()
            self.load_rsa_key_entry.clear()
            self.account_user_entry.clear()
            self.save_btn.setEnabled(False)
            self.mfa_verify_btn.setEnabled(False)

            # Clear data from all properties
            self.tag = None
            self.user = None
            self.file = None
            self.path = None
            self.nonce = None
            self.s_key = None
            self.vault = None
            self.save = None
            self.pubkey = None
            self.userid = None
            self.username = None
            self.temp_pub = None
            self.mfa_check = None
            self.ciphertext = None
            self.session_key = None

            self.ask_to_remove()

    def ask_to_remove(self):
        msg = QMessageBox()

        msg.setWindowTitle("Remove acount from database?")
        msg.setText("""Would you also like to remove your accout from the database? (Yes to delete/No if
        if you just want a backup copy of your account.)""")
        msg.setIcon(QMessageBox.Question)
        msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)

        msg.buttonClicked.connect(self.ask_remove_popup_button)

        msg.exec_()

    def ask_remove_popup_button(self, i):
        v_passwd = get_reg_key()
        if i.text() == '&Yes':
            self.remove_user()
        else:
            user_db_enc('users.db', v_passwd)
            back_to_main()

    # Done
    def remove_popup(self):
        msg = QMessageBox()

        msg.setWindowTitle("Do you want to delete your private key?")
        msg.setText("""Your accout has been deleted! Do you also want to remove your private key? (Yes to delete/No if
if you need to backup your private key)""")
        msg.setIcon(QMessageBox.Question)
        msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)

        msg.buttonClicked.connect(self.remove_popup_button)

        msg.exec_()

    # Done
    def remove_popup_button(self, i):
        v_passwd = get_reg_key()
        if i.text() == '&Yes':
            key = Path(self.private_key)
            os.remove(key)
            user_db_enc('users.db', v_passwd)
            back_to_main()
        else:
            user_db_enc('users.db', v_passwd)
            back_to_main()


class User:
    def __init__(self): # prikey=None, pubkey=None, s_key=None, vault=None, userid=None
        self.s_key = None # s_key
        self.userid = None # userid
        self.pri_key = None # prikey
        self.pub_key = None # pubkey
        self.locked = True
        self.unlocked = False
        self.vault = None # Path(vault)

    def update_rsa(self):
        pass

    def lock_vault(self):
        passwd = rsa_vault_decrypt(self.pri_key, self.userid)
        aes_encrypt(self.vault, passwd)
        v_passwd = get_reg_key()
        if v_passwd:
            user_db_enc('users.db', v_passwd)
        self.locked = True

    def unlock_vault(self):
        v_passwd = get_reg_key()
        if v_passwd:
            try:
                user_db_dec('users.db', v_passwd)
            except:
                pass
            passwd = rsa_vault_decrypt(self.pri_key, self.userid)
            self.unlocked = aes_decrypt(self.vault, passwd)

        if self.unlocked:
            self.locked = False
            self.unlocked = True

        return self.unlocked


# Done
def back_to_main():
    widget.addWidget(main_window)
    widget.setCurrentIndex(widget.currentIndex()+1)


def exit_handler():
    print("Now Exiting")
    if not main_window.vault_user.locked:
        main_window.vault_user.lock_vault()

    sys.exit(0)


def is_root():
    return os.getuid() == 0


if __name__ == '__main__':
    if not get_reg_flag():
        elevate(show_console=False)
        create_vault_key()
        create_db()
        sys.exit(0)

    app = QApplication([])
    widget = QtWidgets.QStackedWidget()
    main_window = UI()
    app.aboutToQuit.connect(exit_handler)
    widget.addWidget(main_window)
    widget.show()
    app.exec_()
