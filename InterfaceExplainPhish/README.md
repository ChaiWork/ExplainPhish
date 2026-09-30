# ExplainPhish — Interface & Inference Layer

## Structure

```
InterfaceExplainPhish/
  extractors/
    __init__.py          package docstring
    base.py              security guards: file-size limit, ZIP-bomb detection
    pdf_extractor.py     static PDF feature extraction (PyMuPDF + pdfminer)
    excel_extractor.py   static Excel feature extraction (openpyxl + xlrd)
    html_extractor.py    static HTML feature extraction (BeautifulSoup)
    word_extractor.py    static Word feature extraction (OOXML ZIP + olefile)
  predict.py             end-to-end model inference, majority voting & SHAP explainability
  parity_test.py         schema validation and extractor sanity checks
```

## Running Inference & Voting (predict.py)

Analyze single files or directories with trained models (Decision Tree, Random Forest, XGBoost), consensus voting, and SHAP decision explanations:

```powershell
cd D:\codingProject\ExplainPhish\InterfaceExplainPhish

# Predict single file
python predict.py --file "..\sample_09994.pdf"

# Predict directory of files
python predict.py --dir "..\path\to\samples\"

# Output structured JSON for web/API integration
python predict.py --file "..\sample_09994.pdf" --json
```

### Output Includes:
- **Detected Format**: Magic byte sniffing (PDF, Word, Excel, HTML)
- **Extracted Features**: Real-time static document parsing
- **Individual Models**: Predictions and malicious probabilities from Decision Tree, Random Forest, and XGBoost
- **Consensus Voting**: Majority vote verdict (`MALICIOUS` / `BENIGN`), confidence score, confidence band (`HIGH` / `MEDIUM` / `LOW`), and agreement/uncertainty flag
- **SHAP Drivers**: Top features explaining why the models voted malicious or benign (risk increase [+] or risk reduction [-])

---

## Parity Test (parity_test.py)

```powershell
cd D:\codingProject\ExplainPhish\InterfaceExplainPhish
python parity_test.py --format pdf   --file "..\sample_09994.pdf"
python parity_test.py --format excel --file "..\sample.xlsx"
python parity_test.py --format all   --dir  "..\samples\"
```

Checks:
- Extractor runs without errors
- All required keys from `models/<format>/selected_features.json` are present
- No extra keys (exact model feature schema alignment)
- All values are numeric (int/float) with no NaN/Inf
- Non-negative counts and plausible entropy ranges (0–8 bits)

---

## Security Controls (base.py)

| Guard | Limit |
|-------|-------|
| Max file size | 50 MB |
| ZIP decompression ratio | 100× |
| ZIP uncompressed ceiling | 500 MB |
| Execution | Never — static parsing only |
| File access | Read-only binary |

---

## Note on leakage (report this)

- **Excel `macro_chr_count`** was removed (AUC = 0.989, threshold 0.985).  
  The extractor does NOT return it. If your lecturer asks, document the
  threshold decision and the fact it was made after seeing full-dataset AUC
  (mild violation of the train-only rule — note it in your report).

- **Word** uses a per-format leakage override (1.001) because lowering the
  global threshold would remove all remaining features. Document as a
  dataset limitation; a real-world Word corpus would fix this.

- **Methodology inconsistency**: PDF and HTML still use the 0.999 threshold;
  Excel uses 0.985; Word uses 1.001. To satisfy the "same methodology for
  every format" requirement, retrain all four with a single agreed threshold
  (e.g. 0.999, restoring the original) and document the Excel decision separately.
