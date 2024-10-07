import streamlit as st
from sw_writer import SWAdapter
from excel_reader import ExcelAdapter
import traceback
import pandas as pd

page_title = "TARA Importer"
st.set_page_config(page_title, page_icon=":copilot:")


def get_uploader():
    return st.file_uploader("Choose the TARA file (Excel)", type="xlsx")


def get_server():
    (
        col1,
        col2,
    ) = st.columns(2)
    with col1:
        address = st.text_input("Server address", value=st.secrets["SW_SERVER"])
    with col2:
        port = st.number_input("Server port", step=1, value=st.secrets["SW_PORT"])

    return address, int(port)


def get_credentials():
    col1, col2 = st.columns(2)
    with col1:
        username = st.text_input("Username", value=st.secrets["SW_USERNAME"])
    with col2:
        password = st.text_input(
            "Password", type="password", value=st.secrets["SW_PASSWORD"]
        )

    return username, password


def get_handles():
    col1, col2 = st.columns(2)
    with col1:
        cs_handle = st.text_input(
            "Cybersecurity Area", value=st.secrets["SW_CSAREA"]
        ).split("/")[-1]
    with col2:
        cslib_handle = st.text_input(
            "Cybersecurity Library", value=st.secrets["SW_CSLIB"]
        ).split("/")[-1]
    return cs_handle, cslib_handle


def get_sids():
    config = {
        "Item Type": st.column_config.TextColumn(
            "Item Type", required=True, help="Type of the item"
        ),
        "Item SID": st.column_config.TextColumn(
            "Item SID",
            required=True,
            help="SID assigned to the item type in the cybersecurity metamodel",
        ),
        "Part Type": st.column_config.TextColumn(
            "Part Type", required=True, help="Type of the part"
        ),
        "Part SID": st.column_config.TextColumn(
            "Part SID",
            required=True,
            help="SID assigned to the part type in the cybersecurity metamodel",
        ),
        "Attribute Type": st.column_config.TextColumn(
            "Attribute Type", required=True, help="Type of the Attribute"
        ),
        "Attribute SID": st.column_config.TextColumn(
            "Attribute SID",
            required=True,
            help="SID assigned to the attribute type in the cybersecurity metamodel",
        ),
    }

    return st.data_editor(
        st.session_state.sids,
        column_config=config,
        hide_index=True,
    )


def render_page():

    st.header(page_title)
    st.divider()
    st.subheader("1. Upload the input file")

    uploaded_file = get_uploader()

    if uploaded_file is not None:
        st.subheader("2. Connect to SystemWeaver")

        server, port = get_server()
        username, password = get_credentials()
        auth_data = {
            "username": username,
            "windowsauthentication": "true",
            "password": password,
            "grant_type": "password",
        }

        if st.button("Connect"):
            with st.spinner("Connecting to SystemWeaver"):
                try:
                    st.session_state.sw_endpoint = SWAdapter(server, port)
                    st.session_state.sw_endpoint.authenticate(auth_data)

                    # st.success("Connected to SystemWeaver!", icon="✅")
                except Exception as e:
                    st.error(f"Error: {e}", icon="🚨")
                    if "sw_endpoint" in st.session_state:
                        del st.session_state.sw_endpoint
                    return
        if "sw_endpoint" in st.session_state and st.session_state.sw_endpoint:
            st.subheader("3. Import data")
            cs_handle, cslib_handle = get_handles()

            st.session_state.sids = pd.read_csv("sids.csv")
            with st.expander("SystemWeaver IDs"):
                st.session_state.sids = get_sids()
            st.session_state.sids.to_csv("sids.csv", index=False)
            if st.button("Import"):
                with st.spinner("Transferring data to SystemWeaver"):

                    try:
                        excel_adapter = ExcelAdapter()
                        data = {
                            "cs_handle": cs_handle,
                            "cslib_handle": cslib_handle,
                            "tara_name": uploaded_file.name.split(".")[0],
                            **excel_adapter.read_data(uploaded_file, "Polestar"),
                        }

                        st.session_state.sw_endpoint.write_data(
                            data,
                            st.session_state.sids,
                        )
                        st.success("Import successful!", icon="✅")

                    except Exception as e:
                        st.error(f"Error: {e}\n{traceback.format_exc()}", icon="🚨")
                        return
    elif "sw_endpoint" in st.session_state:
        del st.session_state.sw_endpoint


render_page()
