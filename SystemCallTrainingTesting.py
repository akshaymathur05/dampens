
# -*- coding: utf-8 -*-
"""
Created on Tue Oct 25 19:18:28 2022

@author: aksha
"""

#import analysis_traces
import import_data_func

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.model_selection import GridSearchCV
from scipy import sparse
import time
import os
import pandas as pd
from sklearn.neural_network import MLPClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn import tree
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import MultinomialNB

from sklearn.metrics import roc_curve, auc, accuracy_score, f1_score
import matplotlib.pyplot as plt



if __name__ == '__main__':  # main function
    
    train_dir_path = str(os.getcwd()) + '\\train\\syscalls_modified\\'
    test_dir_path = str(os.getcwd()) + '\\test\\syscalls_modified\\'


    train_malicious_master_path = train_dir_path + 'malicious\\'
    train_benign_master_path =  train_dir_path + 'benign\\'
    test_malicious_master_path = test_dir_path + 'malicious\\'
    test_benign_master_path =  test_dir_path + 'benign\\'
    

    # get all the addresses of malicious traces and benign traces
    train_malicious_file = []
    train_benign_file = []
    test_malicious_file = []
    test_benign_file = []


    train_malicious_file = import_data_func.get_dir(train_malicious_master_path, train_malicious_file)
    train_benign_file = import_data_func.get_dir(train_benign_master_path, train_benign_file)
    test_malicious_file = import_data_func.get_dir(test_malicious_master_path, test_malicious_file)
    test_benign_file = import_data_func.get_dir(test_benign_master_path, test_benign_file)


    # generate original data lists and label lists
    start_load_data = time.time()
    pkgName_m_train,x1_train, y1_train, m_label_tr = import_data_func.load_malicious_data(train_malicious_file, 'Train')  # malicious data and labels
    pkgName_b_train,x2_train, y2_train, b_label_tr = import_data_func.load_benign_data(train_benign_file, 'Train')  # benign data and labels
    pkgName_m_test,x1_test, y1_test, m_label_te = import_data_func.load_malicious_data(test_malicious_file, 'Test')  # malicious data and labels
    pkgName_b_test,x2_test, y2_test, b_label_te = import_data_func.load_benign_data(test_benign_file, 'Test')  # benign data and labels



    end_load_data = time.time()

    # output the results
#    print('There are ' + str(len(x1)) + ' malicious traces')
#    print('There are ' + str(len(x2)) + ' benign traces')

    # filter out the trace that is longer than 500
    start_select_data = time.time()
    pkgName_m_train, x1_train, y1_train, m_label_tr = import_data_func.select_length_over_500_traces(pkgName_m_train,x1_train, y1_train, m_label_tr)
    pkgName_b_train, x2_train, y2_train, b_label_tr = import_data_func.select_length_over_500_traces(pkgName_b_train,x2_train, y2_train, b_label_tr)
    pkgName_m_test, x1_test, y1_test, m_label_te = import_data_func.select_length_over_500_traces(pkgName_m_test,x1_test, y1_test, m_label_te)
    pkgName_b_test, x2_test, y2_test, b_label_te = import_data_func.select_length_over_500_traces(pkgName_b_test,x2_test, y2_test, b_label_te)

    # combine x1, x2 and x3, y1, y2 and y3
    pkgName_train = pkgName_m_train + pkgName_b_train
    x_train = x1_train + x2_train
    y_train = y1_train + y2_train
    label_train = m_label_tr + b_label_tr

    pkgName_test = pkgName_m_test + pkgName_b_test
    x_test = x1_test + x2_test
    y_test = y1_test + y2_test
    label_test = m_label_te + b_label_te


    pkgName =  pkgName_train + pkgName_test
    x = x_train + x_test
    y = y_train + y_test
    label = label_train + label_test


    # select first 100/200/300/400/500 system calls of each trace for attack data
    #REMOVE THE # BELOW TO TRAIN MODELS BASED ON A CERTAIN TRACE LENGTH AND PLOT ROC CURVES
    #x = import_data_func.cut_the_trace_by_window(x, 500)
    #x = import_data_func.cut_the_trace_by_window(x, 1000)
    #x = import_data_func.cut_the_trace_by_window(x, 2000)
    #x = import_data_func.cut_the_trace_by_window(x, 3000)
    x = import_data_func.cut_the_trace_by_window(x, 4000)
    #x = import_data_func.cut_the_trace_by_window(x, 5000)
    end_select_data = time.time()

    # feature extraction and feature union
    start_feature_extraction = time.time()
    # vectorizer_1gram = TfidfVectorizer(min_df=1)  # applying 5-gram TF-IDF vectorizer
    # vectorizer_2gram = TfidfVectorizer(min_df=1, ngram_range=(2, 2))  # applying 2-gram TF-IDF vectorizer
    # vectorizer_3gram = TfidfVectorizer(min_df=1, ngram_range=(3, 3))  # applying 3-gram TF-IDF vectorizer
    #vectorizer_4gram = TfidfVectorizer(min_df=1, ngram_range=(4, 4))  # applying 3-gram TF-IDF vectorizer
    vectorizer_234gram = TfidfVectorizer(min_df=1, ngram_range=(2, 4))

    # x_1gram = vectorizer_1gram.fit_transform(x)
    # x_2gram = vectorizer_2gram.fit_transform(x)
    # x_3gram = vectorizer_3gram.fit_transform(x)
    #x_4gram = vectorizer_4gram.fit_transform(x)
    x_234gram = vectorizer_234gram.fit_transform(x)

    # x_1gram = x_1gram.toarray()
    # x_2gram = x_2gram.toarray()
    # x_3gram = x_3gram.toarray()
    #X_4gram = x_4gram.toarray()
    x_union = x_234gram.toarray()

    # x_union = sparse.hstack([x_2gram, x_3gram, x_4gram])
    # x_union = sparse.hstack([x_3gram, x_4gram])
    end_feature_extraction = time.time()

    dataset = pd.DataFrame(x_union)
    dataset.insert(0, 'pkgName', pkgName)
    dataset.insert(1, 'label', label)
    dataset.insert(len(dataset.columns),'Result', y)
    
    train_dataset = dataset[dataset['label'] == 'Train']    
    test_dataset = dataset[dataset['label'] == 'Test']
    
    train_dataset = train_dataset.drop(['label'], axis = 1)
    train_dataset = train_dataset.set_index(['pkgName'])
    train_dataset.to_csv(train_dir_path+"SyscallsTrainData.txt", sep = ',')

    test_dataset = test_dataset.drop(['label'], axis = 1)
    test_dataset.to_csv(test_dir_path+"SyscallsTestData.txt", index = False, sep = ',')

    
    y = train_dataset['Result']
    X = train_dataset.drop(['Result'], axis = 1)



    # input data splitting
    # select 80% of the data as training data and 20% as validation data
    x_train, x_test, y_train, y_test = train_test_split(X, y, train_size=0.8, test_size=0.2,
                                                            stratify=y)  # print(np.shape(x_train))


    # Random forest classifier and validation
    # define the parameters for rf classifier
    #parameters_rf = [{'n_estimators': [100,200,300],  # 100
    #                'criterion': ['entropy', 'gini'],  # 'gini', 'entropy'
    #                'min_samples_split': [2,3,4,5,6,7],
    #                'random_state': [200]
    #                }]

    # prior parameters: (n_estimators=10, max_depth=None, min_samples_split=2, random_state=0)
    # define the rf classifier
    rfClf = RandomForestClassifier(n_estimators=10, criterion="entropy", min_samples_split=2, random_state=0)

    # define the grid search cv, and training
    
    start_rf_training = time.time()
    rfClf.fit(x_train, y_train)
    end_rf_training = time.time()


    # get the scores with the best parameters
    # print out the best parameters, best score and rf report
    # training report
    y_predict_rf = rfClf.predict(x_test)
    rf_report = classification_report(y_test, y_predict_rf, digits=6)
    rf_acc = accuracy_score(y_test, y_predict_rf)*100
    rf_fScore = f1_score(y_test,y_predict_rf)

    print('\n\nRF: \n\nClassification Report:\n\n'+ str(rf_report) +"\n\nAccuracy:" + str(rf_acc) + "\n\nF1-Score:" + str(rf_fScore))

    # MLP classifier and validation
    # define the parameters for mlp classifier
    #parameters_mlp = {'hidden_layer_sizes': [(2, 1000)],
    #                'activation': ['tanh'],  # 'tanh' - 3gram, 'relu' - 2gram
    #                'solver': ['adam'],  # 'adam', 'lbfgs', 'sgd'
    #                'learning_rate_init': [0.0001],
    #                'beta_1': [0.9],
    #                'beta_2': [0.999],
    #                'epsilon': [1e-8],
    #                'max_iter': [2000]
   #                 }
    
   
   # prior parameters: (hidden_layer_sizes=(2, 1000), activation='tanh', solver='adam', learning_rate_init=0.0001,
    # beta_1=0.9, beta_2=0.999, epsilon=1e-8, max_iter=2000)
    # define the mlp classifier
    mlpClf = MLPClassifier(hidden_layer_sizes = (2, 1000), activation='tanh', learning_rate_init = 0.0001, beta_1 = 0.9, beta_2 = 0.999, epsilon= 1e-8, max_iter = 2000)

    # define the grid search cv, and training
    start_mlp_training = time.time()
    mlpClf.fit(x_train, y_train)
    end_mlp_training = time.time()

    # get the best parameters
    y_predict_mlp = mlpClf.predict(x_test)
    mlp_report = classification_report(y_test, y_predict_mlp, digits=6)
    #print("Accuracy from MLP classifier: %0.5f (+/- %0.5f)" % (
    #    scores_mlp.mean(), gsMlp.cv_results_['std_test_score'][0] * 2))
    mlp_acc = accuracy_score(y_test, y_predict_mlp)*100
    mlp_fScore = f1_score(y_test,y_predict_mlp)

    print('\n\nMLP: \n\nClassification Report:\n\n'+ str(mlp_report) +"\n\nAccuracy:" + str(mlp_acc) + "\n\nF1-Score:" + str(mlp_fScore))


#    print(mlp_report)

    # svm classifier and validation
    # define the parameters for svm classifier
    #parameters_svm = {'gamma': ['auto'],  # auto
    #                  'kernel': ['linear'],  # 'linear' or 'rbf'
    #                  'C': [10],  # 1 or 10
    #                  'probability': [True]
    #                  }

    # define the svm classifier
    svmClf = SVC(gamma='auto', kernel = 'linear', C = 10, probability = True)

    # define the grid search cv, and training
    svmClf.fit(x_train, y_train)

    # get the best parameters
    # svm_best = gsSvm.best_estimator_

    # get the scores with the best parameters
    # print out the best parameters, best score and svm report
    #scores_svm = gsSvm.best_score_
    y_predict_svm = svmClf.predict(x_test)
    svm_report = classification_report(y_test, y_predict_svm, digits=6)
    #print("Accuracy from SVM classifier: %0.5f (+/- %0.5f)" % (scores_svm.mean(), scores_svm.std() * 2))
    svm_acc = accuracy_score(y_test, y_predict_svm)*100
    svm_fScore = f1_score(y_test,y_predict_svm)

    print('\n\nSVM: \n\nClassification Report:\n\n'+ str(svm_report) +"\n\nAccuracy:" + str(svm_acc) + "\n\nF1-Score:" + str(svm_fScore))

    
    #print(svm_report)

    # Decision tree classifier and validation
    # define the parameters for dt classifier
    #parameters_dt = {'criterion': ['gini'],  # 'gini' - random, 'entropy' - best
    #                 'splitter': ['random']  # 'best', 'random'
     #                }

    # prior parameters: none
    # define the dt classifier
    dtClf = tree.DecisionTreeClassifier(criterion = 'gini', splitter = 'random')

    # define the grid search cv, and training
    #gsDt = GridSearchCV(dtClf, parameters_dt, n_jobs=-1, cv=10)
    dtClf.fit(x_train, y_train)

    # get the best parameters
    #dt_best = gsDt.best_estimator_

    # get the scores with the best parameters
    # print out the best parameters, best score and dt report
    #scores_dt = gsDt.best_score_
    y_predict_dt = dtClf.predict(x_test)
    dt_report = classification_report(y_test, y_predict_dt, digits=6)
    #print("Accuracy from Decision tree classifier: %0.5f (+/- %0.5f)" % (scores_dt.mean(), scores_dt.std() * 2))
    dt_acc = accuracy_score(y_test, y_predict_dt)*100
    dt_fScore = f1_score(y_test,y_predict_dt)

    print('\n\nDT: \n\nClassification Report:\n\n'+ str(dt_report) +"\n\nAccuracy:" + str(dt_acc) + "\n\nF1-Score:" + str(dt_fScore))

    
    
    #print(dt_report)

    # K-Neighbors classifier and validation
    # define the parameters for KNN classifier
    #parameters_KNN = {'n_neighbors': [5],  # 3, 5, 7, 10
    #                  'weights': ['distance'],
    #                  'algorithm': ['auto'],
    #                  'p': [2]
    #                  }

    # define the MNB classifier
    knnClf = KNeighborsClassifier(n_neighbors=5, weights = 'distance', algorithm = 'auto', p = 2)

    # define the grid search cv, and training
#    gsKNN = GridSearchCV(KNNClf, parameters_KNN, n_jobs=-1, cv=10)
    knnClf.fit(x_train, y_train)

    # get the best parameters
    # KNN_best = KNNRf.best_estimator_

    # get the scores with the best parameters
    # print out the best parameters, best score and rf report
    #scores_KNN = gsKNN.best_score_
    y_predict_KNN = knnClf.predict(x_test)
    KNN_report = classification_report(y_test, y_predict_KNN, digits=6)
    #print("Accuracy from KNN classifier: %0.5f (+/- %0.5f)" % (scores_KNN.mean(), scores_KNN.std() * 2))
    knn_acc = accuracy_score(y_test, y_predict_KNN)*100
    knn_fScore = f1_score(y_test,y_predict_KNN)

    print('\n\nKNN: \n\nClassification Report:\n\n'+ str(KNN_report) +"\n\nAccuracy:" + str(knn_acc) + "\n\nF1-Score:" + str(knn_fScore))

    
    
    
    #print(KNN_report)

    # Multinomial Naive Bayes classifier and validation
    # define the parameters for MNB classifier
    #parameters_MNB = {'alpha': [0.1]}  # 0.05, 0.1-, 0.3-, 0.5-, 1, 1.2, 1.5, 1.7

    # define the MNB classifier
    mnbClf = MultinomialNB(alpha = 0.1)

    # define the grid search cv, and training
    #gsMNB = GridSearchCV(MNBClf, parameters_MNB, n_jobs=-1, cv=10)
    mnbClf.fit(x_train, y_train)

    # get the best parameters
    # MNB_best = MNBRf.best_estimator_

    # get the scores with the best parameters
    # print out the best parameters, best score and rf report
    #scores_MNB = gsMNB.best_score_
    y_predict_MNB = mnbClf.predict(x_test)
    MNB_report = classification_report(y_test, y_predict_MNB, digits=6)
    #print("Accuracy from MNB classifier: %0.5f (+/- %0.5f)" % (scores_MNB.mean(), scores_MNB.std() * 2))
  
    mnb_acc = accuracy_score(y_test, y_predict_MNB)*100
    mnb_fScore = f1_score(y_test,y_predict_MNB)

    print('\n\nMNB: \n\nClassification Report:\n\n'+ str(MNB_report) +"\n\nAccuracy:" + str(mnb_acc)+ "\n\nF1-Score:" + str(mnb_fScore))
    
    
    #print(MNB_report)




#    
    # print('Loading data time: %0.5f' % (end_load_data - start_load_data))
    # print('System call selection time: %0.5f' % (end_select_data - start_select_data))
    # print('Feature extraction time: %0.5f' % (end_feature_extraction - start_feature_extraction) + '\n')
    # print('Random Forest classifier training time: %0.5f' % (end_rf_training - start_rf_training))
    # print('MLP classifier training time: %0.5f' % (end_mlp_training - start_mlp_training))

    # plot roc curve
    
#     rf test report
    y_pred_rf = rfClf.predict_proba(x_test)[:, 1] # probabilities
    fpr_rf, tpr_rf, thresholds_rf = roc_curve(y_test, y_pred_rf)
    auc_rf = auc(fpr_rf, tpr_rf)

    # mlp test report
    y_pred_mlp = mlpClf.predict_proba(x_test)[:, 1] # probabilities
    fpr_mlp, tpr_mlp, thresholds_mlp = roc_curve(y_test, y_pred_mlp)
    auc_mlp = auc(fpr_mlp, tpr_mlp)

    # svm test report
    y_pred_svm = svmClf.predict_proba(x_test)[:, 1] # probabilities
    fpr_svm, tpr_svm, thresholds_svm = roc_curve(y_test, y_pred_svm)
    auc_svm = auc(fpr_svm, tpr_svm)

    # dt test report
    y_pred_dt = dtClf.predict_proba(x_test)[:, 1] # probabilities
    fpr_dt, tpr_dt, thresholds_dt = roc_curve(y_test, y_pred_dt)
    auc_dt = auc(fpr_dt, tpr_dt)

    # KNN test report
    y_pred_knn = knnClf.predict_proba(x_test)[:, 1] # probabilities
    fpr_knn, tpr_knn, thresholds_knn = roc_curve(y_test, y_pred_knn)
    auc_knn = auc(fpr_knn, tpr_knn)

    # MNB test report
    y_pred_mnb = mnbClf.predict_proba(x_test)[:, 1] # probabilities
    fpr_mnb, tpr_mnb, thresholds_mnb = roc_curve(y_test, y_pred_mnb)
    auc_mnb = auc(fpr_mnb, tpr_mnb)

    # plot
    plt.figure(figsize=(6, 6))
    plt.plot([0, 1], [0, 1], 'k--')
    plt.plot(fpr_rf, tpr_rf, label='RF (area = {:.3f})'.format(auc_rf))
    plt.plot(fpr_mlp, tpr_mlp, label='MLP (area = {:.3f})'.format(auc_mlp))
    plt.plot(fpr_svm, tpr_svm, label='SVM (area = {:.3f})'.format(auc_svm))
    plt.plot(fpr_dt, tpr_dt, label='DT (area = {:.3f})'.format(auc_dt))
    plt.plot(fpr_knn, tpr_knn, label='KNN (area = {:.3f})'.format(auc_knn))
    plt.plot(fpr_mnb, tpr_mnb, label='MNB (area = {:.3f})'.format(auc_mnb))
    plt.xticks(fontsize = 16)
    plt.yticks(fontsize = 16)
    
    plt.xlabel('False positive rate', fontsize = 16)
    plt.ylabel('True positive rate (Detection Rate)', fontsize = 16)
    plt.legend(loc='best', fontsize = 14)
#    plt.show()
    plt.savefig('roc_all.png', format='png', dpi = 1000)

#    import joblib
#    
#    joblib.dump(mlpClf, str(os.getcwd())+"\\sys_mlp_classifier.pkl")
