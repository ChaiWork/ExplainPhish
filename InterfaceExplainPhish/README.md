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

## Overview

ExplainPhish provides static analysis, feature extraction, standard scaling, and multi-model consensus voting across 4 major document formats:
- **HTML** (`.html`, `.htm`)
- **PDF** (`.pdf`)
- **Excel** (`.xlsx`, `.xlsm`, `.xls`, `.xlsb`)
- **Word** (`.docx`, `.docm`, `.doc`)

### Standardized Inference Pipeline
1. **Feature Extraction**: Static parsing without dynamic execution (file size limit: 50MB, zip bomb protection).
2. **StandardScaler Alignment**: Raw feature values are transformed using the fitted scaler from training ($z = \frac{x - \mu}{\sigma}$), preventing scale explosion and ensuring zero training-serving skew.
3. **Multi-Model Inferences**: Evaluated simultaneously by **Random Forest**, **Decision Tree**, and **Logistic Regression**.
4. **Consensus Voting**: Hard majority vote ($\ge 2/3$) decides the verdict (`MALICIOUS` vs `BENIGN`), complemented by soft probability averaging, confidence bands (`HIGH`, `MEDIUM`, `LOW`), and directional risk drivers ($w_j \times z_j$).

## Running Inference & Voting (predict.py)

Analyze single files or entire directories:

```powershell
cd D:\codingProject\ExplainPhish\InterfaceExplainPhish

# Predict single file (automatic format detection & magic byte sniffing)
python predict.py --file "Sample\pbenign_pdf\i1040nre.pdf"
python predict.py --file "Sample\pmalicios_pdf\sample_07602.pdf"
python predict.py --file "Sample\hMalicious_HTML\sample_00195.html"
python predict.py --file "Sample\eBenign_Excel\benign_sample_1244.xlsx"

# Predict directory of files (recursively discovers test documents)
python predict.py --dir "Sample"
python predict.py --dir "Sample\pmalicios_pdf"

# Output structured JSON for API / web interface integration
python predict.py --file "Sample\pbenign_pdf\i1040nre.pdf" --json
```

### Output Includes:
- **Detected Format**: Suffix and magic signature detection
- **Extracted Features**: Real-time static document parsing
- **Standardized Z-Scores**: Calibrated deviations from the training baseline
- **Individual Models**: Predictions and malicious probabilities from Random Forest, Decision Tree, and Logistic Regression
- **Consensus Voting**: Majority vote verdict (`MALICIOUS` / `BENIGN`), confidence score, confidence band (`HIGH` / `MEDIUM` / `LOW`), and agreement status
- **Top Decision Drivers**: Top features driving the prediction with their directionality (`[+] Increases Risk` vs `[-] Reduces Risk`) and standardized impact score

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
