# -*- coding: utf-8 -*-
"""
Created on Thu Oct 27 10:11:58 2022

@author: aksha
"""


#import analysis_traces
#import import_data_func

#from sklearn.feature_extraction.text import TfidfVectorizer
#from sklearn.metrics import classification_report
import time
import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
#from sklearn.tree import DecisionTreeClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import cross_validate
import joblib

from sklearn.metrics import roc_curve, auc, accuracy_score,f1_score,confusion_matrix
from sklearn.metrics import classification_report
import matplotlib.pyplot as plt
import numpy as np



def prepareSystemCalls(directory_path):
    sub_dir = directory_path+'\\train\\syscalls_modified\\'
    dataset = pd.read_csv(sub_dir + 'SyscallsTrainData.txt', sep = ',')
    
    dataset = dataset.set_index(['pkgName'])
    
    return dataset
    


def prepareNTD(directory_path):
    
    sub_dir = directory_path + "\\train\\pcaps\\"    
    data = pd.read_csv(sub_dir + "filtered_pcapDataset_PostCorr.csv")
    
    #Merge Datasets
    data = data.rename(columns={'apkNum':'pkgName'})
    data['pkgName'] = data['pkgName'].str.replace('.pcap', '')
    
    #removing duplicates and summing up their values
    dataset = data.groupby(['pkgName'], as_index = False).agg('sum')
    
    #Final data cleaning
    dataset.loc[dataset['Result'] >1, 'Result'] = 1
    dataset = dataset.set_index(['pkgName'])
    
    return dataset
    
    
def preparePerms(directory_path):
    sub_dir = directory_path + "\\train\\PermsCsv\\"    
    dataset = pd.read_csv(sub_dir + "PermsDataset_PostCorr.csv")
    i = dataset[(dataset['pkgName']=='0-com.til.ooty_guide') & (dataset['android.permission.ACCESS_WIFI_STATE'] == 0)]
    dataset = dataset.drop(i.index, axis = 0)
    dataset = dataset.drop_duplicates()    
 
    return dataset
    
 
def training(key, dataset, classifier):

    y = dataset['Result']
    X = dataset.drop(['Result'], axis = 1)
        
    start_training = time.time()
    classifier.fit(X, y)
    end_training = time.time()
    
    print(key + " Trianing Time: " + str(end_training - start_training))

    return classifier

def modelling(classifier, dataset):
    y = dataset['Result']
    X = dataset.drop(['Result'], axis = 1)
   
    train_start = time.time() 
    classifier.fit(X, y)
    train_end = time.time()
    trn_time = train_end - train_start
    
    scoring = ['accuracy', 'f1']
    
    detction_start = time.time()
    val = cross_validate(estimator = classifier, X = X, y = y, scoring=scoring, cv = 5, n_jobs = -1)
    detection_end = time.time()
    tst_time = detection_end - detction_start
        
    
    return val['test_accuracy'].mean()*100, val['test_f1'].mean(), trn_time, tst_time

    
if __name__ == '__main__':
    
    directory_path = str(os.getcwd())
    
    
    sys_dataset = prepareSystemCalls(directory_path)
    ntd_dataset = prepareNTD(directory_path)
    perms_dataset = preparePerms(directory_path)
    perms_dataset = perms_dataset.set_index(['pkgName'])
    
    sys_index = list(sys_dataset.index)
    ntd_index = list(ntd_dataset.index)
    perms_index = list(perms_dataset.index)
    
    temp = list(set(sys_index)&set(ntd_index)&set(perms_index))
    
    sys_dataset = sys_dataset.loc[temp]
    ntd_dataset = ntd_dataset.loc[temp]
    perms_dataset = perms_dataset.loc[temp]


    sys_models = {
         'LR': LogisticRegression(C = 1.0,penalty='l2',solver='liblinear', random_state=42, n_jobs = -1),
         'KN': KNeighborsClassifier(n_neighbors=5, weights = 'distance', algorithm = 'auto', p = 2),
         'SV': SVC(gamma='auto', kernel = 'linear', C = 10, probability = True, random_state=42),
         'RF': RandomForestClassifier(n_estimators=500, criterion="entropy", min_samples_split=2, random_state=42, n_jobs=-1),
         'MLP': MLPClassifier(hidden_layer_sizes = (2, 1000), activation='tanh', learning_rate_init = 0.0001, beta_1 = 0.9, beta_2 = 0.999, epsilon= 1e-8, max_iter = 3000),
         'XG': XGBClassifier(learning_rate= 0.1, max_depth= 4, min_child_weight= 1, n_estimators= 100, subsample= 1.0,n_jobs = -1),
         }
    
    ntd_models = {
         'LR': LogisticRegression(C = 1.0,penalty='l2',solver='liblinear', random_state=42, n_jobs = -1),
         'KN': KNeighborsClassifier(n_neighbors=4, weights='distance', metric = 'manhattan'),
         'SV': SVC(kernel = 'rbf', C=6, random_state=42,probability=True),
         'RF': RandomForestClassifier(criterion='gini', max_depth=6, min_samples_leaf = 1, min_samples_split = 6,random_state = 42, n_estimators=300, n_jobs = -1),
         'MLP': MLPClassifier(hidden_layer_sizes = (2, 1000), activation='tanh', learning_rate_init = 0.0001, beta_1 = 0.9, beta_2 = 0.999, epsilon= 1e-8, max_iter = 3000),
         'XG': XGBClassifier(learning_rate= 0.1, max_depth= 4, min_child_weight= 1, n_estimators= 100, subsample= 1.0,n_jobs = -1),
            }

    perms_models = {
         'LR': LogisticRegression(C = 0.1,penalty='l2',solver='liblinear', random_state=42, n_jobs = -1),
         'KN': KNeighborsClassifier(n_neighbors=2, weights='uniform', metric = 'manhattan'),
         'SV': SVC(kernel = 'rbf', C=1, random_state=42,probability=True),
         'RF': RandomForestClassifier(criterion='gini', max_depth=6, min_samples_leaf = 1, min_samples_split = 5,random_state = 0, n_estimators=50, n_jobs = -1),
         'MLP': MLPClassifier(hidden_layer_sizes = (2, 1000), activation='tanh', learning_rate_init = 0.0001, beta_1 = 0.9, beta_2 = 0.999, epsilon= 1e-8, max_iter = 3000),
         'XG': XGBClassifier(learning_rate= 0.2, max_depth= 3, min_child_weight= 1, n_estimators= 50, subsample= 1.0,n_jobs = -1),
         }
    
    
    column_names = ['Classifier', 'CV Accuracy', 'Test F-Score', 'Training Time', 'CV Time']      #Metrics for each test size
    results = []

    for key,classifier in ntd_models.items():
        val_acc, fScore, trn_time, tst_time = modelling(classifier, ntd_dataset)
        temp = []
        temp.append(key)
        temp.append(val_acc)
        temp.append(fScore)
        temp.append(trn_time)
        temp.append(tst_time)
        results.append(temp)
    df1 = pd.DataFrame(results, columns = column_names)
    df1.to_csv(directory_path+"\\train\\pcaps\\ntd_results.csv")

    results = []

    for key,classifier in perms_models.items():
        val_acc, fScore, trn_time, tst_time = modelling(classifier, perms_dataset)
        temp = []
        temp.append(key)
        temp.append(val_acc)
        temp.append(fScore)
        temp.append(trn_time)
        temp.append(tst_time)
        results.append(temp)
    df2 = pd.DataFrame(results, columns = column_names)
    df2.to_csv(directory_path+"\\train\\PermsCsv\\perms_results.csv")


    results = []

    for key,classifier in sys_models.items():
        val_acc, fScore, trn_time, tst_time = modelling(classifier, sys_dataset)
        temp = []
        temp.append(key)
        temp.append(val_acc)
        temp.append(fScore)
        temp.append(trn_time)
        temp.append(tst_time)
        results.append(temp)
    df3 = pd.DataFrame(results, columns = column_names)
    df3.to_csv(directory_path+"\\train\\syscalls_modified\\sys_calls_results.csv")


    sys_classifier = MLPClassifier(hidden_layer_sizes = (2, 1000), activation='tanh', learning_rate_init = 0.0001, beta_1 = 0.9, beta_2 = 0.999, epsilon= 1e-8, max_iter = 2000)
    ntd_classifier = XGBClassifier(learning_rate= 0.2, max_depth= 4, min_child_weight= 1, n_estimators= 100, subsample= 1.0,n_jobs = -1)
    perms_classifier = SVC(kernel = 'rbf', C=1, random_state=42,probability=True)

    sysClf = training("sys",sys_dataset, sys_classifier)
    ntdClf = training("ntd",ntd_dataset, ntd_classifier) 
    permsClf = training("perms",perms_dataset, perms_classifier) 
    

    joblib.dump(sysClf, 'sys_classifer.pkl')
    print("Pkl Saved")
    joblib.dump(ntdClf, 'ntd_classifer.pkl')
    print("Pkl Saved")
    joblib.dump(permsClf, 'perms_classifer.pkl')
    print("Pkl Saved")    
    
    
    
    
    
    
    
    
    
    
    
    
