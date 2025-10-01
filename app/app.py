"""
Kisumu County Referral Hospital
Inventory & Pharmacy Tracker - Streamlit app (single-file)

Features:
- SQLite database (kisumu_inventory.db) with tables: users, drugs, suppliers, transactions
- User roles: admin, pharmacist, viewer
- Drug CRUD (add/edit/delete)
- Supplier CRUD
- Restock (IN) and Dispense (OUT) transactions
- Low-stock & expiry alerts
- Dashboard with summary cards and simple charts
- Export reports to CSV

Run:
    pip install streamlit pandas plotly openpyxl
    streamlit run kisumu_inventory_app.py

Default admin credentials created on first run:
    username: admin
    password: admin123

This file is an MVP — adjust to your hospital's policies and security requirements before using in production.
"""

import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime, date, timedelta
import hashlib
import io
import os
import plotly.express as px

DB_PATH = "kisumu_inventory.db"

# -----------------------------
# Database helpers
# -----------------------------

def get_db_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_conn()
    cur = conn.cursor()

    # users table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        full_name TEXT
    )
    ''')

    # suppliers
    cur.execute('''
    CREATE TABLE IF NOT EXISTS suppliers (
        supplier_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        contact TEXT,
        email TEXT,
        address TEXT
    )
    ''')

    # drugs
    cur.execute('''
    CREATE TABLE IF NOT EXISTS drugs (
        drug_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        category TEXT,
        unit TEXT,
        stock_quantity INTEGER DEFAULT 0,
        reorder_level INTEGER DEFAULT 0,
        batch_number TEXT,
        expiry_date TEXT
    )
    ''')

    # transactions
    cur.execute('''
    CREATE TABLE IF NOT EXISTS transactions (
        transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
        drug_id INTEGER,
        type TEXT CHECK(type IN ('IN','OUT')),
        quantity INTEGER,
        date TEXT,
        reference TEXT,
        details TEXT,
        supplier_id INTEGER,
        user_id INTEGER,
        FOREIGN KEY(drug_id) REFERENCES drugs(drug_id),
        FOREIGN KEY(supplier_id) REFERENCES suppliers(supplier_id),
        FOREIGN KEY(user_id) REFERENCES users(user_id)
    )
    ''')

    conn.commit()

    # Create default admin if not exists
    cur.execute("SELECT COUNT(*) as c FROM users")
    if cur.fetchone()[0] == 0:
        # default admin
        create_user('admin', 'admin123', 'admin', full_name='Kisumu Admin')
        st.info('Default admin created: username=admin password=admin123')

    conn.close()


# -----------------------------
# Authentication
# -----------------------------

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def create_user(username, password, role='viewer', full_name=None):
    conn = get_db_conn()
    cur = conn.cursor()
    pw_hash = hash_password(password)
    try:
        cur.execute("INSERT INTO users (username, password_hash, role, full_name) VALUES (?,?,?,?)",
                    (username, pw_hash, role, full_name))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def authenticate(username, password):
    conn = get_db_conn()
    cur = conn.cursor()
    pw_hash = hash_password(password)
    cur.execute("SELECT user_id, username, role, full_name FROM users WHERE username=? AND password_hash=?",
                (username, pw_hash))
    row = cur.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None


# -----------------------------
# CRUD & operations
# -----------------------------

def add_supplier(name, contact=None, email=None, address=None):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO suppliers (name, contact, email, address) VALUES (?,?,?,?)",
                (name, contact, email, address))
    conn.commit()
    conn.close()


def get_suppliers():
    conn = get_db_conn()
    df = pd.read_sql_query("SELECT * FROM suppliers ORDER BY name", conn)
    conn.close()
    return df


def add_drug(name, category, unit, stock_quantity=0, reorder_level=0, batch_number=None, expiry_date=None):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute('''INSERT INTO drugs (name, category, unit, stock_quantity, reorder_level, batch_number, expiry_date)
                   VALUES (?,?,?,?,?,?,?)''',
                (name, category, unit, stock_quantity, reorder_level, batch_number, expiry_date))
    conn.commit()
    conn.close()


def update_drug(drug_id, **kwargs):
    keys = []
    vals = []
    for k, v in kwargs.items():
        keys.append(f"{k}=?")
        vals.append(v)
    vals.append(drug_id)
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute(f"UPDATE drugs SET {', '.join(keys)} WHERE drug_id=?", vals)
    conn.commit()
    conn.close()


def delete_drug(drug_id):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM drugs WHERE drug_id=?", (drug_id,))
    conn.commit()
    conn.close()


def get_drugs_df():
    conn = get_db_conn()
    df = pd.read_sql_query("SELECT * FROM drugs ORDER BY name", conn)
    conn.close()
    return df


def record_transaction(drug_id, tx_type, quantity, reference=None, details=None, supplier_id=None, user_id=None):
    assert tx_type in ('IN', 'OUT')
    conn = get_db_conn()
    cur = conn.cursor()
    date_str = datetime.now().isoformat()
    cur.execute('''INSERT INTO transactions (drug_id, type, quantity, date, reference, details, supplier_id, user_id)
                   VALUES (?,?,?,?,?,?,?,?)''',
                (drug_id, tx_type, quantity, date_str, reference, details, supplier_id, user_id))

    # update stock
    if tx_type == 'IN':
        cur.execute("UPDATE drugs SET stock_quantity = stock_quantity + ? WHERE drug_id=?", (quantity, drug_id))
    else:
        cur.execute("UPDATE drugs SET stock_quantity = stock_quantity - ? WHERE drug_id=?", (quantity, drug_id))

    conn.commit()
    conn.close()


def get_transactions_df(limit=500):
    conn = get_db_conn()
    df = pd.read_sql_query('''SELECT t.transaction_id, t.drug_id, d.name as drug_name, t.type, t.quantity, t.date, t.reference, t.details, s.name as supplier, u.username as user
                              FROM transactions t
                              LEFT JOIN drugs d ON t.drug_id=d.drug_id
                              LEFT JOIN suppliers s ON t.supplier_id=s.supplier_id
                              LEFT JOIN users u ON t.user_id=u.user_id
                              ORDER BY t.date DESC
                              LIMIT ?''', conn, params=(limit,))
    conn.close()
    return df


# -----------------------------
# Utilities
# -----------------------------

def to_csv_bytes(df: pd.DataFrame) -> bytes:
    return df.to_csv(index=False).encode('utf-8')


def to_excel_bytes(df: pd.DataFrame) -> bytes:
    with io.BytesIO() as towrite:
        writer = pd.ExcelWriter(towrite, engine='openpyxl')
        df.to_excel(writer, index=False, sheet_name='Sheet1')
        writer.save()
        return towrite.getvalue()


# -----------------------------
# Streamlit App
# -----------------------------

st.set_page_config(page_title="Kisumu Inventory & Pharmacy", layout='wide')

init_db()

if 'auth_user' not in st.session_state:
    st.session_state['auth_user'] = None

# ----- Sidebar: Login / User info -----
with st.sidebar:
    st.title('Kisumu Inventory')
    if st.session_state['auth_user'] is None:
        st.subheader('Login')
        username = st.text_input('Username')
        password = st.text_input('Password', type='password')
        if st.button('Login'):
            user = authenticate(username.strip(), password)
            if user:
                st.session_state['auth_user'] = user
                st.success(f"Logged in as {user['username']} ({user['role']})")
                st.rerun()

            else:
                st.error('Invalid credentials')
        st.write('---')
        st.subheader('Create user (admin only)')
        st.info('If no users exist, default admin created automatically.')
        # quick create user for first-time admin
        cu_name = st.text_input('New username')
        cu_pw = st.text_input('New password', type='password')
        cu_role = st.selectbox('Role', ['viewer', 'pharmacist', 'admin'])
        cu_full = st.text_input('Full name')
        if st.button('Create user'):
            # only allow if logged in as admin OR if no users exist
            conn = get_db_conn()
            cur = conn.cursor()
            cur.execute('SELECT COUNT(*) as c FROM users')
            count = cur.fetchone()['c']
            conn.close()
            allow = False
            if st.session_state['auth_user'] and st.session_state['auth_user'].get('role') == 'admin':
                allow = True
            if count == 0:
                allow = True
            if not allow:
                st.error('Only admin can create users')
            else:
                ok = create_user(cu_name.strip(), cu_pw, cu_role, full_name=cu_full)
                if ok:
                    st.success('User created')
                else:
                    st.error('Could not create user (username exists?)')
    else:
        user = st.session_state['auth_user']
        st.write(f"**{user.get('full_name') or user['username']}**")
        st.write(f"Role: {user['role']}")
        if st.button('Logout'):
            st.session_state['auth_user'] = None
            st.rerun()


# ----- Main -----
st.title('Kisumu County Referral Hospital — Inventory & Pharmacy Tracker')

# tabs
tabs = st.tabs(['Dashboard', 'Inventory', 'Transactions', 'Suppliers', 'Reports', 'Settings'])

# -----------------------------
# Dashboard
# -----------------------------
with tabs[0]:
    st.header('Dashboard')
    df_drugs = get_drugs_df()

    total_items = int(df_drugs['stock_quantity'].sum()) if not df_drugs.empty else 0
    distinct_drugs = len(df_drugs)

    # low stock
    low_stock_df = df_drugs[df_drugs['stock_quantity'] <= df_drugs['reorder_level']]

    # expired / expiring
    today = date.today()
    def parse_date(s):
        try:
            return datetime.fromisoformat(s).date()
        except Exception:
            return None
    df_drugs['expiry_parsed'] = df_drugs['expiry_date'].apply(lambda x: parse_date(x) if x else None)
    expired = df_drugs[df_drugs['expiry_parsed'].notnull() & (df_drugs['expiry_parsed'] < today)]
    expiring_30 = df_drugs[df_drugs['expiry_parsed'].notnull() & (df_drugs['expiry_parsed'] <= today + timedelta(days=30)) & (df_drugs['expiry_parsed'] >= today)]

    c1, c2, c3, c4 = st.columns(4)
    c1.metric('Total stock (units)', f"{total_items}")
    c2.metric('Distinct drugs', f"{distinct_drugs}")
    c3.metric('Low stock items', f"{len(low_stock_df)}")
    c4.metric('Expired/expiring (30d)', f"{len(expired) + len(expiring_30)}")

    st.subheader('Low stock (reorder)')
    st.dataframe(low_stock_df[['drug_id','name','stock_quantity','reorder_level','unit']])

    st.subheader('Expired / Expiring soon')
    st.dataframe(pd.concat([expired, expiring_30])[['drug_id','name','stock_quantity','expiry_date']])

    # simple usage chart (last 90 days)
    tx_df = get_transactions_df(limit=1000)
    if not tx_df.empty:
        tx_df['date_parsed'] = pd.to_datetime(tx_df['date']).dt.date
        recent = tx_df[(tx_df['type']=='OUT') & (tx_df['date_parsed'] >= (today - timedelta(days=90)))]
        if not recent.empty:
            top_used = recent.groupby('drug_name')['quantity'].sum().reset_index().sort_values('quantity', ascending=False).head(10)
            st.subheader('Top dispensed drugs (90d)')
            fig = px.bar(top_used, x='drug_name', y='quantity', labels={'drug_name':'Drug','quantity':'Qty dispensed'})
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info('No dispensing transactions in last 90 days')
    else:
        st.info('No transactions recorded yet')

# -----------------------------
# Inventory management
# -----------------------------
with tabs[1]:
    st.header('Inventory')
    role = st.session_state['auth_user']['role'] if st.session_state['auth_user'] else 'viewer'

    st.subheader('Add new drug')
    with st.form('add_drug'):
        name = st.text_input('Drug name')
        category = st.text_input('Category')
        unit = st.text_input('Unit (e.g., tablets, bottles)')
        stock_quantity = st.number_input('Initial stock quantity', min_value=0, value=0)
        reorder_level = st.number_input('Reorder level (alert threshold)', min_value=0, value=10)
        batch = st.text_input('Batch number (optional)')
        expiry = st.date_input('Expiry date (optional)', value=None)
        submitted = st.form_submit_button('Add drug')
        if submitted:
            if not name:
                st.error('Name required')
            else:
                expiry_str = expiry.isoformat() if expiry else None
                add_drug(name.strip(), category.strip() or None, unit.strip() or None, int(stock_quantity), int(reorder_level), batch.strip() or None, expiry_str)
                st.success('Drug added')

    st.subheader('Current stock')
    df = get_drugs_df()
    st.dataframe(df)

    st.subheader('Edit / Delete drug')
    edit_id = st.number_input('Enter Drug ID to edit/delete (see table above)', min_value=0, value=0)
    if edit_id > 0:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute('SELECT * FROM drugs WHERE drug_id=?', (edit_id,))
        row = cur.fetchone()
        conn.close()
        if row:
            r = dict(row)
            with st.form('edit_drug'):
                new_name = st.text_input('Name', value=r['name'])
                new_cat = st.text_input('Category', value=r['category'] or '')
                new_unit = st.text_input('Unit', value=r['unit'] or '')
                new_stock = st.number_input('Stock quantity', min_value=0, value=int(r['stock_quantity']))
                new_reorder = st.number_input('Reorder level', min_value=0, value=int(r['reorder_level']))
                new_batch = st.text_input('Batch', value=r['batch_number'] or '')
                try:
                    existing_expiry = datetime.fromisoformat(r['expiry_date']).date() if r['expiry_date'] else None
                except Exception:
                    existing_expiry = None
                new_expiry = st.date_input('Expiry date (leave as-is to keep)', value=existing_expiry) if existing_expiry else st.date_input('Expiry date (optional)', value=None)
                save = st.form_submit_button('Save changes')
                delete = st.form_submit_button('Delete drug')
                if save:
                    expiry_str = new_expiry.isoformat() if new_expiry else None
                    update_drug(edit_id, name=new_name.strip(), category=new_cat.strip() or None, unit=new_unit.strip() or None, stock_quantity=int(new_stock), reorder_level=int(new_reorder), batch_number=new_batch.strip() or None, expiry_date=expiry_str)
                    st.success('Updated')
                if delete:
                    if role != 'admin':
                        st.error('Only admin can delete drugs')
                    else:
                        delete_drug(edit_id)
                        st.success('Deleted')
        else:
            st.warning('Drug not found')

# -----------------------------
# Transactions
# -----------------------------
with tabs[2]:
    st.header('Transactions (Restock / Dispense)')
    df_drugs = get_drugs_df()
    drugs_map = {r['drug_id']: r['name'] for _, r in df_drugs.iterrows()} if not df_drugs.empty else {}

    st.subheader('Record transaction')
    with st.form('tx_form'):
        tx_type = st.selectbox('Type', ['IN','OUT'])
        drug_choice = st.selectbox('Drug', options=list(drugs_map.keys()), format_func=lambda x: f"{x} - {drugs_map[x]}") if drugs_map else st.selectbox('Drug', options=[0])
        qty = st.number_input('Quantity', min_value=1, value=1)
        supplier_df = get_suppliers()
        supplier_choice = st.selectbox('Supplier (for IN)', options=[0] + supplier_df['supplier_id'].tolist() if not supplier_df.empty else [0], format_func=lambda x: 'None' if x==0 else supplier_df[supplier_df['supplier_id']==x]['name'].iloc[0])
        reference = st.text_input('Reference / PO #')
        details = st.text_area('Notes')
        submit_tx = st.form_submit_button('Record')
        if submit_tx:
            if not st.session_state['auth_user']:
                st.error('Login required')
            else:
                uid = st.session_state['auth_user']['user_id'] if 'user_id' in st.session_state['auth_user'] else None
                record_transaction(int(drug_choice), tx_type, int(qty), reference.strip() or None, details.strip() or None, int(supplier_choice) if supplier_choice else None, uid)
                st.success('Transaction recorded')

    st.subheader('Recent transactions')
    tx_df = get_transactions_df(limit=500)
    st.dataframe(tx_df)

# -----------------------------
# Suppliers
# -----------------------------
with tabs[3]:
    st.header('Suppliers')
    st.subheader('Add supplier')
    with st.form('add_supplier'):
        sname = st.text_input('Name')
        scontact = st.text_input('Contact')
        semail = st.text_input('Email')
        saddr = st.text_area('Address')
        add_ok = st.form_submit_button('Add supplier')
        if add_ok:
            if not sname:
                st.error('Name required')
            else:
                add_supplier(sname.strip(), scontact.strip() or None, semail.strip() or None, saddr.strip() or None)
                st.success('Supplier added')

    st.subheader('All suppliers')
    st.dataframe(get_suppliers())

# -----------------------------
# Reports
# -----------------------------
with tabs[4]:
    st.header('Reports & Export')
    st.subheader('Export current stock')
    df = get_drugs_df()
    if not df.empty:
        st.download_button('Download CSV', data=to_csv_bytes(df), file_name='current_stock.csv', mime='text/csv')
        st.download_button('Download Excel', data=to_excel_bytes(df), file_name='current_stock.xlsx', mime='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

    st.subheader('Export transactions (filter)')
    tx_df = get_transactions_df(limit=5000)
    if not tx_df.empty:
        start = st.date_input('Start date', value=today - timedelta(days=30))
        end = st.date_input('End date', value=today)
        filtered = tx_df[pd.to_datetime(tx_df['date']).dt.date.between(start, end)]
        st.write(f"Transactions in range: {len(filtered)}")
        st.dataframe(filtered)
        st.download_button('Download CSV', data=to_csv_bytes(filtered), file_name='transactions_export.csv', mime='text/csv')

# -----------------------------
# Settings
# -----------------------------
with tabs[5]:
    st.header('Settings')
    st.subheader('Database info')
    st.write('DB path:', DB_PATH)
    st.write('File exists:', os.path.exists(DB_PATH))

    st.subheader('Advanced')
    if st.button('Re-initialize DB (danger: will keep data - only creates tables if missing)'):
        init_db()
        st.success('DB initialized (tables ensured)')

    st.subheader('Danger Zone')
    if st.session_state['auth_user'] and st.session_state['auth_user'].get('role') == 'admin':
        if st.button('Purge ALL data (DROP tables)'):
            conn = get_db_conn()
            cur = conn.cursor()
            cur.executescript('''
            DROP TABLE IF EXISTS transactions;
            DROP TABLE IF EXISTS drugs;
            DROP TABLE IF EXISTS suppliers;
            DROP TABLE IF EXISTS users;
            ''')
            conn.commit()
            conn.close()
            st.warning('All tables dropped. Re-initialize app to recreate tables.')
    else:
        st.info('Only admin can see destructive operations')

    st.write('---')
    st.write('Notes: This app uses a local SQLite file. For multi-user hospital deployment use a proper server DB (Postgres/MySQL) and secure authentication + HTTPS.')

# Footer
st.markdown('---')
st.caption('Built for Kisumu County Referral Hospital — Inventory & Pharmacy Tracker. Adjust fields and security before production use.')
