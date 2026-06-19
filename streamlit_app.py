import pandas as pd
import streamlit as st

from baseline_rules import analyze_dataframe


APP_VERSION = "0.1"
REQUIRED_COLUMNS = [
    "ComputerName",
    "TPM",
    "SecureBoot",
    "BitLocker",
    "Defender",
    "Firewall",
    "OSVersion",
    "LocalAdminCount",
]


def load_devices(csv_file):
    return pd.read_csv(csv_file)


def build_results_dataframe(results):
    rows = []
    for result in results:
        rows.append(
            {
                "ComputerName": result["ComputerName"],
                "SecurityScore": result["SecurityScore"],
                "RiskLevel": result["RiskLevel"],
                "HighestSeverity": result["HighestSeverity"],
                "Findings": "; ".join(result["Findings"]) if result["Findings"] else "None",
                "Recommendations": " | ".join(result["Recommendations"]) if result["Recommendations"] else "No action needed.",
            }
        )
    return pd.DataFrame(rows)


def get_missing_columns(df):
    return [column for column in REQUIRED_COLUMNS if column not in df.columns]


def show_score_cards(results_df):
    total_devices = len(results_df)
    healthy_devices = int((results_df["RiskLevel"] == "Low").sum()) if not results_df.empty else 0
    at_risk_devices = int((results_df["RiskLevel"].isin(["Medium", "High"])).sum()) if not results_df.empty else 0
    critical_devices = int((results_df["RiskLevel"] == "Critical").sum()) if not results_df.empty else 0
    average_score = round(results_df["SecurityScore"].mean(), 1) if not results_df.empty else 0

    cols = st.columns(5)
    cols[0].metric("Devices", total_devices)
    cols[1].metric("Healthy", healthy_devices)
    cols[2].metric("At Risk", at_risk_devices)
    cols[3].metric("Critical", critical_devices)
    cols[4].metric("Average Score", average_score)

    if average_score >= 90:
        st.success("Overall posture looks strong. Weirdly responsible behavior from a fleet of endpoints.")
    elif average_score >= 75:
        st.warning("Overall posture is decent, but there are enough issues here to keep security people twitchy.")
    else:
        st.error("Overall posture is weak. Something in this device fleet is making attackers feel emotionally supported.")


def show_overview(results_df):
    st.subheader("Risk overview")
    risk_counts = results_df["RiskLevel"].value_counts().rename_axis("RiskLevel").reset_index(name="Count")
    st.bar_chart(risk_counts.set_index("RiskLevel"))
    st.dataframe(risk_counts, width="stretch")

    st.subheader("Top findings")
    findings = []
    for value in results_df["Findings"]:
        if value == "None":
            continue
        findings.extend([item.strip() for item in value.split(";") if item.strip()])

    if findings:
        findings_df = pd.Series(findings).value_counts().rename_axis("Finding").reset_index(name="Count")
        st.bar_chart(findings_df.set_index("Finding"))
        st.dataframe(findings_df, width="stretch")
    else:
        st.success("No findings detected.")


def show_devices(results_df):
    st.subheader("Device details")
    col1, col2 = st.columns(2)
    with col1:
        search = st.text_input("Search computer name")
    with col2:
        risk_filter = st.selectbox("Risk level", ["All", "Low", "Medium", "High", "Critical"])

    filtered_df = results_df.copy()
    if search:
        filtered_df = filtered_df[filtered_df["ComputerName"].astype(str).str.contains(search, case=False, na=False)]
    if risk_filter != "All":
        filtered_df = filtered_df[filtered_df["RiskLevel"] == risk_filter]

    st.dataframe(filtered_df, width="stretch")
    st.download_button(
        "Download Filtered Results CSV",
        data=filtered_df.to_csv(index=False).encode("utf-8"),
        file_name="secure_my_stuff_filtered_results.csv",
        mime="text/csv",
        key="download_filtered_results",
    )


def show_recommendations(results_df):
    st.subheader("Recommended actions")
    risky_df = results_df[results_df["Findings"] != "None"].copy()

    if risky_df.empty:
        st.success("No recommendations needed. Enjoy this rare moment before the next audit ruins it.")
        return

    st.dataframe(
        risky_df[["ComputerName", "RiskLevel", "Findings", "Recommendations"]],
        width="stretch",
    )

    st.download_button(
        "Download Recommendations CSV",
        data=risky_df.to_csv(index=False).encode("utf-8"),
        file_name="secure_my_stuff_recommendations.csv",
        mime="text/csv",
        key="download_recommendations",
    )


def show_import_help():
    st.subheader("CSV format")
    st.write("Secure My Stuff v0.1 expects these columns:")
    st.code(",".join(REQUIRED_COLUMNS), language="text")
    st.write("Example:")
    st.code(
        "ComputerName,TPM,SecureBoot,BitLocker,Defender,Firewall,OSVersion,LocalAdminCount\n"
        "PC001,True,True,True,True,True,Windows 11,1\n"
        "PC002,True,False,False,True,True,Windows 10,4",
        language="csv",
    )


def main():
    st.set_page_config(page_title="Secure My Stuff", layout="wide")
    st.title("Secure My Stuff")
    st.caption(f"Security Baseline Auditor | Version {APP_VERSION}")

    uploaded_file = st.file_uploader("Upload device security CSV", type=["csv"])
    use_sample = st.checkbox("Use sample data", value=uploaded_file is None)

    df = None
    if uploaded_file is not None:
        try:
            df = load_devices(uploaded_file)
        except Exception as error:
            st.error(f"Unable to read uploaded CSV: {error}")
    elif use_sample:
        try:
            df = load_devices("data/sample_devices.csv")
            st.info("Loaded sample data from data/sample_devices.csv")
        except Exception as error:
            st.error(f"Unable to load sample data: {error}")

    if df is None:
        show_import_help()
        return

    missing_columns = get_missing_columns(df)
    if missing_columns:
        st.error("Missing required columns: " + ", ".join(missing_columns))
        show_import_help()
        return

    results = analyze_dataframe(df)
    results_df = build_results_dataframe(results)

    show_score_cards(results_df)

    overview_tab, devices_tab, recommendations_tab, import_help_tab = st.tabs(
        ["Overview", "Devices", "Recommendations", "Import Help"]
    )

    with overview_tab:
        show_overview(results_df)

    with devices_tab:
        show_devices(results_df)

    with recommendations_tab:
        show_recommendations(results_df)

    with import_help_tab:
        show_import_help()


if __name__ == "__main__":
    main()
