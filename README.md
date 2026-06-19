# Secure My Stuff

Secure My Stuff is a lightweight Streamlit security baseline auditor for endpoint posture review.

Version 0.1 supports CSV-based device assessment for common security controls:

- TPM
- Secure Boot
- BitLocker
- Microsoft Defender
- Windows Firewall
- OS version risk
- Local administrator count

## Quick Start

```bash
pip install -r requirements.txt
python -m streamlit run streamlit_app.py --server.address 0.0.0.0
```

## CSV Format

The app expects a CSV with these columns:

```csv
ComputerName,TPM,SecureBoot,BitLocker,Defender,Firewall,OSVersion,LocalAdminCount
PC001,True,True,True,True,True,Windows 11,1
PC002,True,False,False,True,True,Windows 10,4
```

## Output

The dashboard provides:

- Device count
- Healthy device count
- At-risk device count
- Critical device count
- Average security score
- Top findings
- Device-level findings
- Recommended actions
- CSV exports

## Roadmap

Planned future versions:

- v0.2: Recommendation engine improvements
- v0.3: SCCM/Intune column normalization
- v0.4: Executive PDF export
- v0.5: Security posture trend history
