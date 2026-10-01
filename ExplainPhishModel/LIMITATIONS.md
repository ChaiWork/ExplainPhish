# ExplainPhish: Dataset Artefacts, Shortcut Learning & Model Limitations

> [!CAUTION]
> **CRITICAL DISCLAIMER: Near-perfect benchmark metrics (99.6%–100%) reflect dataset-level separability and synthetic/schema collection artefacts in CIC-Trap4Phish2025, NOT real-world deployment efficacy.**
> Models trained on this dataset will overfit to collection signatures and fail when deployed against in-the-wild phishing attacks that do not share these synthetic patterns or specific parser idiosyncrasies.

---

## Executive Summary

ExplainPhish evaluates machine learning models (XGBoost, Random Forest, Decision Tree) on the **CIC-Trap4Phish2025** benchmark across four document formats: **PDF, Word, Excel, and HTML**. 

Prior iterations of the training pipeline exhibited near-100% accuracy on Word (100%), Excel (99.9%), and PDF (99.6%), alongside a per-format bypass policy (`LEAKAGE_AUC_REMOVE_OVERRIDE = {"word": 1.001}`) that disabled leakage protection exclusively for Word documents.

To ensure scientific honesty and rigor:
1. **Per-format overrides were eliminated**, establishing a single unified policy across all formats.
2. **Leakage & shortcut detection was moved strictly into the training split (60% train, 5-fold CV)**, ensuring the 40% test set remains pristine and untouched for evaluation only.
3. **A comprehensive shortcut and missingness audit (`src/shortcut_audit.py`) was created**, identifying single-feature AUCs, depth-1 decision stump CV scores, tree dominance, missingness correlation, and feature colinearities.
4. **Controlled ablation experiments (`ablation.py`) and external evaluation tools (`external_eval.py`)** were introduced.

---

## 1. Per-Format Audit Findings & Dataset Artefacts

### 1.1 Word Documents (`Word_All_features.csv`): Disjoint XML Schema Split & Macro Polarization

* **Sample Size**: 20,000 raw samples (10,000 Benign, 10,000 Malicious). 3,395 duplicate feature rows fell entirely on the benign class (6,605 unique benign vs 10,000 malicious).
* **The Root Cause of 100% Scores**:
  1. **Disjoint XML Schemas**: 30 out of 43 features have missing values (225,310 missing cells total). In every single missing column, the missingness indicator AUC against the label is **exactly 1.0**:
     * `path_w*` and `struct_{...wordprocessingml...}` columns are populated for **100% of benign rows** and **0% of malicious rows**.
     * `path_a*` and drawing-related `struct_*` columns are populated for **0% of benign rows** and **100% of malicious rows**.
     * `pd.crosstab(label, has_both_w_and_a_xml)` shows that **0 files** in the entire dataset contain both. The two classes were extracted using completely disjoint XML parser routines or document template types.
  2. **Extreme Single-Feature Leakage**: 10 features have single-feature train AUC $\ge 0.985$:
     * `ole_object_count` (AUC 1.0, Stump F1 1.0)
     * `ole_object_type_count` (AUC 1.0, Stump F1 1.0)
     * `vba_keywords_count` (AUC 1.0, Stump F1 1.0)
     * `macro_present` (AUC 0.9999, Stump F1 0.9999)
     * `entropy` (AUC 0.9997)
     * `dde_present` (AUC 0.9995)
     * `struct_ContentType` (AUC 0.9976)
     * `struct_PartName` (AUC 0.9955)
     * `file_size` (AUC 0.9919)
     * `struct_val` (AUC 0.9868)
  3. **Model Collusion / Lack of Diversity**: All three models (XGBoost, Random Forest, Decision Tree) produced **100% identical test predictions** (mean pairwise disagreement = 0.00%, 0 test samples where all models were wrong).
  4. **Why Feature Removal Alone Does Not Lower Word Scores**: Even when all 10 high-AUC macro/proxy features are excised (Ablation Variant e), surviving tree models latch directly onto the remaining XML schema split features (`path_w*`, `path_a*`), achieving 99.91%–100% F1.

### 1.2 Excel Documents (`Excel_All_Features.csv`): Synthetic Generator Signatures

* **Sample Size**: 20,000 raw samples. 6,028 duplicate feature rows existed, heavily concentrated in benign files (benign undersampled from 10,000 to 3,972 after deduplication).
* **The Root Cause of 99.9% Scores**:
  1. **Synthetic Benign Templates**: The benign Excel files originate from `Generated_benign_excels_10000/`. The generator produced documents with rigid, artificial characteristics:
     * `remote_template_present` = 1 for 100% of benign files.
     * `empty_sheet_count` = 1 for 100% of benign files.
     * `macro_chr_count`, `macro_token_count`, `macro_vocab_size` = 0 for 100% of benign files.
  2. **Dominant Shortcuts Flagged by Audit**:
     * `macro_chr_count` (train AUC = 0.9934) captures **90.7% of all decision tree feature importance**, immediately triggering the `likely_shortcut` alert.
     * 4 features exceed the 0.985 AUC threshold: `macro_chr_count`, `macro_token_count`, `macro_vocab_size`, and `macro_arithmetic_operator_count`.
  3. **Survival of Secondary Shortcuts**: When the 4 high-AUC macro features are removed, the models pivot seamlessly to secondary generator artifacts (`entropy_of_text`, `string_cell_count`, `numeric_cell_count`, `remote_template_present`), maintaining 99.8% F1.

### 1.3 PDF Documents (`PDF_All_Features.csv`): Structural Separation

* **Sample Size**: 20,000 raw samples (9,679 unique rows after removing 10,321 duplicate feature rows; balanced to 4,839 per class).
* **Audit Findings**:
  * Zero features exceed the 0.985 AUC threshold. Highest single-feature AUC is `object_count` (0.9430) and `metadata_size` (0.9296).
  * No single feature holds $\ge 90\%$ decision tree importance (`likely_shortcut = false`).
  * While individual features do not trivially separate classes, a combination of structural counts (`object_count`, `stream_count`, `total_filters`, `text_length`) achieves 99.6% F1.
  * Mean ensemble pairwise disagreement is 0.33%; 8 test samples (0.16%) fool all three models simultaneously.

### 1.4 HTML Documents (`HTML_All_Features.csv`): The Honest Baseline

* **Sample Size**: 19,997 raw samples (15,404 unique rows; 4,581 duplicates removed; balanced to 5,785 per class).
* **Audit Findings**:
  * Zero features exceed the 0.985 AUC threshold. Highest single-feature AUC is `url_punct_char_count` (0.8309) and `external_links_count` (0.8245).
  * `likely_shortcut = false`.
  * **Real-World Behavior**: HTML is derived from live web crawling (PhishTank vs Alexa). Because it lacks synthetic generator shortcuts or parser schema splits, performance is natural:
    * XGBoost: **88.16% F1** (AUC 0.9528, FPR 11.0%)
    * Random Forest: **87.69% F1** (AUC 0.9498, FPR 12.0%)
    * Decision Tree: **84.69% F1** (AUC 0.9085, FPR 17.5%)
  * **Healthy Ensemble Diversity**: Mean pairwise disagreement is **7.25%**, and **384 test samples (8.3%)** are misclassified by all three models. This confirms HTML represents a realistic, non-shortcut classification problem.

---

## 2. Word OOXML-Only Experiment (`src/word_ooxml_experiment.py`)

A hypothesis was tested: *Are the missing values in Word caused by legacy binary (.doc) files lacking OOXML structure? If we restrict analysis to documents containing XML parts, does the dataset normalize?*

### Crosstab Analysis on Raw Word Dataset (20,000 Rows):

```
Crosstab 1: has_any_path_xml (any path_* column is non-null)
has_any_path_xml   True
label                  
0                 10000
1                 10000

Crosstab 2: has_wordprocessingml_xml (path_w* / path_/w*)
has_wordprocessingml_xml  False  True 
label                                 
0                             0  10000
1                         10000      0

Crosstab 3: has_drawingml_xml (path_a* / path_/a*)
has_drawingml_xml  False  True 
label                          
0                  10000      0
1                      0  10000

Crosstab 4: has_both_w_and_a_xml
has_both_w_and_a_xml  False
label                      
0                     10000
1                     10000
```

### Findings & Decision:
1. **Every single document (100% Benign, 100% Malicious) contains XML parts**. The missingness is **not** caused by legacy `.doc` vs modern `.docx` formats.
2. Instead, the benign and malicious corpora underwent **asymmetric XML feature extraction**: the feature extractor parsed WordprocessingML elements exclusively on benign files, and DrawingML elements exclusively on malicious files.
3. Because both classes satisfied the $\ge 500$ row threshold (10,000 rows each), the OOXML subset model was trained and evaluated under `results_word_ooxml_only/`. 
4. The resulting OOXML model still achieved **100% test accuracy** because the disjoint schema extraction artefact is present across all OOXML files in the dataset.

---

## 3. Ablation Experiments

All ablation variants were trained using 5-fold Stratified Cross-Validation on the **training split only** (`random_state=42`), with final evaluation on the untouched 40% test set:
* **Variant a (baseline)**: All cleaned features.
* **Variant b (without_macro_ole_dde)**: Excluding `ole_object_count`, `ole_object_type_count`, `macro_present`, `vba_keywords_count`, `dde_present`.
* **Variant c (without_format_proxies)**: Excluding `entropy`, `file_size`, `struct_pos`, `struct_ContentType`, `struct_PartName`.
* **Variant d (without_macro_and_proxies)**: Excluding both b and c.
* **Variant e (without_audit_flagged)**: Excluding all features flagged with train single-feature AUC $\ge 0.985$.

### 3.1 Word Ablation Results

| Variant | Model | Features | 5-Fold CV F1 (Mean ± Std) | 5-Fold CV AUC | Test F1 (Reporting Only) | Test AUC (Reporting Only) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **a_baseline** | XGBoost | 43 | 0.9999 ± 0.0003 | 1.0000 | 1.0000 | 1.0000 |
| | Random Forest | 43 | 1.0000 ± 0.0000 | 1.0000 | 1.0000 | 1.0000 |
| | Decision Tree | 43 | 1.0000 ± 0.0000 | 1.0000 | 1.0000 | 1.0000 |
| **b_without_macro_ole_dde** | XGBoost | 38 | 0.9996 ± 0.0003 | 1.0000 | 1.0000 | 1.0000 |
| | Random Forest | 38 | 0.9999 ± 0.0003 | 1.0000 | 1.0000 | 1.0000 |
| | Decision Tree | 38 | 0.9991 ± 0.0006 | 0.9999 | 0.9996 | 1.0000 |
| **c_without_format_proxies** | XGBoost | 38 | 0.9999 ± 0.0003 | 1.0000 | 1.0000 | 1.0000 |
| | Random Forest | 38 | 1.0000 ± 0.0000 | 1.0000 | 1.0000 | 1.0000 |
| | Decision Tree | 38 | 1.0000 ± 0.0000 | 1.0000 | 1.0000 | 1.0000 |
| **d_without_macro_and_proxies** | XGBoost | 33 | 1.0000 ± 0.0000 | 1.0000 | 0.9998 | 1.0000 |
| | Random Forest | 33 | 1.0000 ± 0.0000 | 1.0000 | 1.0000 | 1.0000 |
| | Decision Tree | 33 | 1.0000 ± 0.0000 | 1.0000 | 0.9998 | 0.9998 |
| **e_without_audit_flagged** | XGBoost | 33 | 0.9997 ± 0.0003 | 1.0000 | 1.0000 | 1.0000 |
| | Random Forest | 33 | 1.0000 ± 0.0000 | 1.0000 | 1.0000 | 1.0000 |
| | Decision Tree | 33 | 0.9995 ± 0.0005 | 0.9996 | 0.9991 | 0.9994 |

---

### 3.2 Excel Ablation Results

| Variant | Model | Features | 5-Fold CV F1 (Mean ± Std) | 5-Fold CV AUC | Test F1 (Reporting Only) | Test AUC (Reporting Only) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **a_baseline** | XGBoost | 42 | 0.9996 ± 0.0005 | 0.9999 | 0.9994 | 1.0000 |
| | Random Forest | 42 | 0.9998 ± 0.0004 | 1.0000 | 0.9991 | 1.0000 |
| | Decision Tree | 42 | 0.9975 ± 0.0008 | 0.9994 | 0.9969 | 0.9984 |
| **c_without_format_proxies** | XGBoost | 41 | 0.9996 ± 0.0005 | 0.9999 | 0.9987 | 1.0000 |
| | Random Forest | 41 | 0.9996 ± 0.0005 | 1.0000 | 0.9991 | 1.0000 |
| | Decision Tree | 41 | 0.9981 ± 0.0012 | 0.9996 | 0.9981 | 0.9997 |
| **d_without_macro_and_proxies** | XGBoost | 41 | 0.9996 ± 0.0005 | 0.9999 | 0.9987 | 1.0000 |
| | Random Forest | 41 | 0.9996 ± 0.0005 | 1.0000 | 0.9991 | 1.0000 |
| | Decision Tree | 41 | 0.9981 ± 0.0012 | 0.9996 | 0.9981 | 0.9997 |
| **e_without_audit_flagged** | XGBoost | 38 | 0.9992 ± 0.0008 | 1.0000 | 0.9987 | 0.9999 |
| | Random Forest | 38 | 0.9998 ± 0.0004 | 1.0000 | 0.9991 | 1.0000 |
| | Decision Tree | 38 | 0.9985 ± 0.0008 | 0.9996 | 0.9975 | 0.9997 |

---

### 3.3 PDF Ablation Results

| Variant | Model | Features | 5-Fold CV F1 (Mean ± Std) | 5-Fold CV AUC | Test F1 (Reporting Only) | Test AUC (Reporting Only) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **a_baseline** | XGBoost | 32 | 0.9963 ± 0.0027 | 0.9995 | 0.9969 | 1.0000 |
| | Random Forest | 32 | 0.9960 ± 0.0021 | 0.9996 | 0.9965 | 0.9999 |
| | Decision Tree | 32 | 0.9942 ± 0.0020 | 0.9974 | 0.9957 | 0.9971 |
| **c_without_format_proxies** | XGBoost | 31 | 0.9968 ± 0.0020 | 0.9990 | 0.9971 | 0.9997 |
| | Random Forest | 31 | 0.9966 ± 0.0025 | 0.9994 | 0.9963 | 0.9999 |
| | Decision Tree | 31 | 0.9944 ± 0.0016 | 0.9968 | 0.9957 | 0.9975 |
| **d_without_macro_and_proxies** | XGBoost | 31 | 0.9968 ± 0.0020 | 0.9990 | 0.9971 | 0.9997 |
| | Random Forest | 31 | 0.9966 ± 0.0025 | 0.9994 | 0.9963 | 0.9999 |
| | Decision Tree | 31 | 0.9944 ± 0.0016 | 0.9968 | 0.9957 | 0.9975 |

---

### 3.4 HTML Ablation Results

| Variant | Model | Features | 5-Fold CV F1 (Mean ± Std) | 5-Fold CV AUC | Test F1 (Reporting Only) | Test AUC (Reporting Only) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **a_baseline** | XGBoost | 40 | 0.9031 ± 0.0078 | 0.9661 | 0.9068 | 0.9680 |
| | Random Forest | 40 | 0.8846 ± 0.0095 | 0.9566 | 0.8890 | 0.9580 |
| | Decision Tree | 40 | 0.8417 ± 0.0131 | 0.9015 | 0.8393 | 0.9076 |
| **c_without_format_proxies** | XGBoost | 38 | 0.9004 ± 0.0072 | 0.9647 | 0.9079 | 0.9670 |
| | Random Forest | 38 | 0.8841 ± 0.0108 | 0.9560 | 0.8877 | 0.9568 |
| | Decision Tree | 38 | 0.8408 ± 0.0122 | 0.8969 | 0.8396 | 0.9108 |
| **d_without_macro_and_proxies** | XGBoost | 38 | 0.9004 ± 0.0072 | 0.9647 | 0.9079 | 0.9670 |
| | Random Forest | 38 | 0.8841 ± 0.0108 | 0.9560 | 0.8877 | 0.9568 |
| | Decision Tree | 38 | 0.8408 ± 0.0122 | 0.8969 | 0.8396 | 0.9108 |

---

## 4. Before & After Pipeline Comparison

| Format | Model | Baseline (`results/`) F1 | Baseline AUC | High-AUC Removed (`results_high_auc_removed/`) F1 | High-AUC Removed AUC | Notes |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **PDF** | XGBoost | 0.9969 | 1.0000 | 0.9969 | 1.0000 | No features flagged $\ge 0.985$ AUC |
| | Random Forest | 0.9967 | 0.9999 | 0.9967 | 0.9999 | No features flagged $\ge 0.985$ AUC |
| | Decision Tree | 0.9953 | 0.9960 | 0.9953 | 0.9960 | No features flagged $\ge 0.985$ AUC |
| **Word** | XGBoost | 1.0000 | 1.0000 | 0.9991 | 1.0000 | 10 features removed; XML schema split persists |
| | Random Forest | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 10 features removed; XML schema split persists |
| | Decision Tree | 1.0000 | 1.0000 | 0.9991 | 0.9994 | 10 features removed; XML schema split persists |
| **Excel** | XGBoost | 0.9987 | 1.0000 | 0.9987 | 0.9999 | 4 macro features removed; synthetic artifacts persist |
| | Random Forest | 0.9984 | 1.0000 | 0.9981 | 1.0000 | 4 macro features removed; synthetic artifacts persist |
| | Decision Tree | 0.9969 | 0.9987 | 0.9975 | 0.9997 | 4 macro features removed; synthetic artifacts persist |
| **HTML** | XGBoost | 0.8816 | 0.9528 | 0.8816 | 0.9528 | Reliable live-crawl data; natural generalization |
| | Random Forest | 0.8769 | 0.9498 | 0.8769 | 0.9498 | Reliable live-crawl data; natural generalization |
| | Decision Tree | 0.8469 | 0.9085 | 0.8469 | 0.9085 | Reliable live-crawl data; natural generalization |

---

## 5. Architectural Integrity & Recommendations

1. **Do Not Treat Benchmark Numbers as Generalizable Performance**:
   * Word and Excel models are learning collection-specific shortcuts. They should **never** be cited in external publications as 99.9% accurate real-world detectors.
   * Only HTML reflects real-world classification difficulty (88% F1 with 11% FPR).
2. **Use the External Evaluation Harness (`external_eval.py`)**:
   * When new, independently collected document samples are available, run:
     ```bash
     python external_eval.py --format <fmt> --csv <path_to_external_features.csv>
     ```
   * Expect substantial performance degradation on Word and Excel when tested on documents not sharing the CIC-Trap4Phish2025 extraction pipelines.
3. **Future Research Directions**:
   * **Unified Document Extraction**: Re-extract Word document features using a unified parser that captures both WordprocessingML and DrawingML attributes symmetrically across all classes.
   * **Adversarial Benign Generation**: Eliminate synthetic Excel templates in favor of authentic in-the-wild business spreadsheets.
