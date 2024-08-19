# Enhanced Web Attack Detection for TANNER: A Machine Learning Approach (Google Summer of Code 2024)

The dataset used in this project is derived from web traffic data collected by SNARE sensors over several years, with annotations based on regular expressions to identify various types of web-based attacks. 

This dataset includes *four* primary types of attacks: 
-	**SQL Injection (SQLi)**: Malicious SQL queries are injected into input fields to manipulate databases
-	**Cross-Site Scripting (XSS)**: Attackers inject malicious scripts into web pages viewed by other users
-	**Local File Inclusion (LFI)**: Exploits vulnerabilities to access files on the server
-	**Remote File Inclusion (RFI)**: Allows attackers to include remote files on a web server
-	**Index**: Normal, benign web requests

To enhance the dataset's robustness and reduce noise and imbalance, supplementary data from external cybersecurity repositories were integrated. The dataset is constructed with 67 features extracted from URLs, followed by preprocessing steps such as label encoding, TF-IDF transformation on a character level, and meticulous cleaning to remove duplicates, address missing values, and eliminate outliers. Despite the imbalanced nature of the dataset, with a higher proportion of normal traffic, it serves as a robust foundation for developing a machine learning-based classifier intended to replace the existing regular expression-based detection in TANNER, aiming for improved accuracy and lower latency in real-time web attack detection. 



**Data Preprocessing**

To prepare the dataset for modeling, I began by addressing any missing values—removing rows where essential data like path and payload were absent, and imputing values in less critical columns with averages or the most frequent entries. Duplicate records were eliminated to ensure the integrity of the dataset, and outliers were either transformed using log scaling or removed entirely if they were deemed erroneous. The target labels, representing different types of web traffic and attacks (SQLi, XSS, LFI, RFI, and normal traffic), were converted into numerical form through label encoding, making them ready for model consumption.

A significant step in the preprocessing was the application of TF-IDF (Term Frequency-Inverse Document Frequency) at the character level to the path and payload columns. This technique helped capture intricate patterns within the URLs and payloads, which are crucial for accurate web attack detection. Normalization and standardization were applied as needed to ensure that the data was on a consistent scale, particularly for features with a wide range of values. These preprocessing steps were crucial in laying a solid foundation for training robust machine learning models.



**Modeling Approach**

I tested several machine learning models on my dataset to determine which one provided the best performance for web attack detection. The models I evaluated include Random Forest, XGBoost, a Multi-layer Neural Network (Dense), LightGBM, and a Decision Tree. Each model was tuned with specific parameters, and their performance was measured using accuracy, f1 score, log loss, and a confusion matrix.

Among the models tested, the Random Forest model stood out as the best performer, achieving an accuracy of **94.48%**, f1 score of **94.18**, with a log loss of 0.1312. This model outperformed others in both accuracy and log loss, making it the optimal choice for further deployment. The confusion matrix for the Random Forest model also showed the best balance in correctly identifying different types of web traffic and attacks.

<img width="489" alt="Screenshot 2024-08-19 at 12 29 18 PM" src="https://github.com/user-attachments/assets/ae034a95-a835-4a0e-8515-53b2de9f0dc4">



**Comparison with Baseline (RegEx)**\
<img width="609" alt="Screenshot 2024-08-19 at 6 03 34 PM" src="https://github.com/user-attachments/assets/9ebf82b3-d4a0-4b43-8f72-e46b37fbe5c1">





- Number of Samples (**Entire Dataset**): 149,488
- Number of Samples (**Train Data**): 104,641
- Number of Samples (**Test Data**): 44,847


Class Distribition Guide: 

- Label 0: Index
- Label 1: LFI 
- Label 2: RFI
- Label 3: SQLi
- Label 4: Unknown
- Label 5: XSS
  
**Entire Dataset** 

Class Distribution\
<img width="192" alt="Screenshot 2024-08-16 at 12 51 11 PM" src="https://github.com/user-attachments/assets/f7a3737e-0a3e-42ad-a701-317c243da1a5">

Statistics: 
[full_data_statistics.csv](https://github.com/user-attachments/files/16646880/full_data_statistics.csv)


**Train Set**

Class Distribution:\
<img width="220" alt="train data label dist" src="https://github.com/user-attachments/assets/5534f301-b193-43dd-b691-71d012d6455f">


Statistics:
[train_data_statistics.csv](https://github.com/user-attachments/files/16646855/train_data_statistics.csv)

**Test Set** 

Class Distribution:\
<img width="203" alt="test data label dist" src="https://github.com/user-attachments/assets/af8b7a65-972b-4532-8a31-9c46135a86d8">

Statistics:
[test_data_statistics.csv](https://github.com/user-attachments/files/16646870/test_data_statistics.csv)

**Future Work**


The Random Forest model’s significant improvement in detecting web-based attacks highlights its potential for enhancing the TANNER system. To integrate this model into TANNER, it could be deployed in many different ways. 

*Microservice*: The Random Forest model can be deployed as a microservice within TANNER's existing architecture. This approach would allow the ML model to analyze incoming web traffic in real-time, alongside or in place of the current regex-based detection. By using a microservice architecture, the model can be updated or replaced independently, ensuring that TANNER remains adaptable to new threats.

*Real-Time Processing & Efficiency*: To ensure that the ML model can handle real-time traffic efficiently, optimizations such as model compression or the use of more lightweight models could be explored. Integrating the model with TANNER’s existing caching mechanisms could also reduce the computational load and improve response times.

*Continuous Learning & Adaptation*: One of the strengths of ML models is their ability to learn from new data. Future work could focus on implementing a pipeline that allows the Random Forest model to be retrained periodically with new attack data, ensuring that it remains up-to-date with the latest threat patterns. Also, we could try out a hybrid approach combining both regex-based and ML-based detection could be explored to leverage the strengths of both methods.

*Neural Network Approaches*: Transformer-based neural networks, known for their ability to capture complex patterns in sequential data, could be employed to further improve detection accuracy. These models, particularly those fine-tuned for cybersecurity, could be integrated into TANNER for more sophisticated threat analysis.

*Ensemble Learning*: Combining the Random Forest model with other models, including neural networks, through ensemble learning could lead to even higher detection rates. By leveraging the strengths of multiple algorithms, TANNER could achieve a more robust and adaptable defense against evolving web threats.

**External Datasets Used**

- [XSS Payload List - Cross Site Scripting Vulnerability Payload List](https://www.kitploit.com/2018/05/xss-payload-list-cross-site-scripting.html)
- [Deep-XSS](https://github.com/das-lab/deep-xss/blob/master/xssed.csvl)
- [RFI Payloads](https://github.com/infosec-au/fuzzdb/blob/master/attack-payloads/rfi/rfi.txt)
- [XSS-attack-detection](https://github.com/shalayiding/XSS-attack-detection-using-deep-learning/blob/main/XSS_dataset_mixed.csv)
- [Cross site scripting XSS dataset for Deep learning](https://www.kaggle.com/datasets/syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning)
- [XSS Payload List](https://github.com/payloadbox/xss-payload-list/blob/master/Intruder/xss-payload-list.txt)
- [LFI Payloads](https://raw.githubusercontent.com/emadshanab/LFI-Payload-List/master/LFI%20payloads.txt)
- [SQL Injection Dataset](https://www.kaggle.com/datasets/sajid576/sql-injection-dataset)
- [sql injection dataset](https://www.kaggle.com/datasets/syedsaqlainhussain/sql-injection-dataset)
- [SQL-Injection-Detection](https://github.com/saptajitbanerjee/SQL-Injection-Detection)
- [Malicious And Benign URLs](https://www.kaggle.com/datasets/siddharthkumar25/malicious-and-benign-urls)
