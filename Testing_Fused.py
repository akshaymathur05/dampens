# -*- coding: utf-8 -*-
"""
Created on Sat Oct 22 15:26:55 2022

@author: aksha
"""


#import analysis_traces
#import import_data_func

#from sklearn.feature_extraction.text import TfidfVectorizer

import time
import os
import pandas as pd
import joblib
import numpy as np
from sklearn.metrics import roc_curve, roc_auc_score, accuracy_score, classification_report, f1_score, confusion_matrix
from sklearn.metrics import ConfusionMatrixDisplay
import matplotlib.pyplot as plt
import seaborn as sns




def prepareSystemCalls(directory_path):
    sub_dir = directory_path+'\\test\\syscalls_modified\\'
    dataset = pd.read_csv(sub_dir + 'SyscallsTestData.txt', sep = ',')
    
    dataset = dataset.set_index(['pkgName'])
    
    return dataset
    
#    y = dataset['Result']
#    X = dataset.drop(['Result'], axis = 1)
#
#    return X, y


def prepareNTD(directory_path):
    
    sub_dir = directory_path + "\\test\\pcaps\\"    
    benign = pd.read_csv(sub_dir + "benign_ntd.csv")
    malicious = pd.read_csv(sub_dir + "filtered_malicious_ntd.csv")
    
    #Merge Datasets
    data = pd.concat([benign, malicious])
    data = data.rename(columns={'apkNum':'pkgName'})
    data['pkgName'] = data['pkgName'].str.replace('.pcap', '')
    
    #removing duplicates and summing up their values
    dataset = data.groupby(['pkgName'], as_index = False).agg('sum')
    
    #Final data cleaning
    dataset.loc[dataset['Result'] >1, 'Result'] = 1
    dataset = dataset.set_index(['pkgName'])
    
    
    dd = pd.read_csv(sub_dir + 'filtered_pcapDataset_PostCorr.csv')
    dd = dd.drop(['apkNum'], axis = 1)
    
    irrelevant = list(set(list(dataset.columns)) - set(list(dd.columns)))
    
    dataset = dataset.drop(irrelevant, axis = 1)
    
    return dataset
    
#    y = dataset['Result']
#    X = dataset.drop(['Result'], axis = 1)
#    
#    return X, y
    
def preparePerms(directory_path):

    sub_dir = directory_path + "\\test\\PermsCsv\\"    
    benign = pd.read_csv(sub_dir + "Perms_Benign.csv")
    malicious = pd.read_csv(sub_dir + "Perms_Malicious.csv")
    
    benign = benign.drop_duplicates()
    malicious = malicious.drop_duplicates()
    
    #Merge Datasets
    dataset = pd.concat([benign, malicious])    
        
    #Final data cleaning
    dataset = dataset.set_index(['pkgName'])
#    dataset = data.drop_duplicates()    
    
    dd = pd.read_csv(sub_dir + 'PermsDataset_PostCorr.csv')
    dd = dd.drop(['pkgName'], axis = 1)
    
    irrelevant = list(set(list(dataset.columns)) - set(list(dd.columns)))
    
    dataset = dataset.drop(irrelevant, axis = 1)
    
    return dataset
#    y = dataset['Result']
#    X = dataset.drop(['Result'], axis = 1)
#    
#    return X, y
    
  
def loadPkls(directory):
    sysClf = joblib.load(directory+"\\sys_classifer.pkl") # Load "model.pkl"
    print ('System Calls Model loaded')
    ntdClf = joblib.load(directory+"\\ntd_classifer.pkl") # Load "model.pkl"
    print ('Network Traffic Model loaded')
    permsClf = joblib.load(directory+"\\perms_classifer.pkl") # Load "model.pkl"
    print ('Permissions Model loaded')

    return sysClf, ntdClf, permsClf


def testing(key, dataset, classifier):

    #sys_lst = []
    y = dataset['Result']
    X = dataset.drop(['Result'], axis = 1)
        
    # get the best parameters
    start_testing = time.time()
    y_predict = classifier.predict(X)
    end_testing = time.time()


    rep = classification_report(y, y_predict, digits=6)
    #print("Accuracy from MLP classifier: %0.5f (+/- %0.5f)" % (
    #    scores_mlp.mean(), gsMlp.cv_results_['std_test_score'][0] * 2))
    acc = accuracy_score(y, y_predict)*100
    fScore = f1_score(y,y_predict)
    cm = confusion_matrix(y, y_predict)

    print('\n\n'+key+': \n\nClassification Report:\n\n'+ str(rep) +"\n\nAccuracy:" + str(acc) + "\n\nF1-Score:" + str(fScore))
    print("Testing Time (in seconds): " + str(end_testing - start_testing))    
        
    probs = classifier.predict_proba(X)
#    probs = probs[:, 1]
    
    prob_ben = key+'_prob_ben'
    prob_mal = key+'_prob_mal'
    y_pred = key+'_y_pred'
    
    df_dict = {
            'pkgName': list(X.index),
            'y_true': y,
            y_pred: y_predict,
            prob_ben: list(probs[:,0]),
            prob_mal: list(probs[:,1])
            }    
    
    results = pd.DataFrame(df_dict)
    results = results.set_index(['pkgName'])

    return results, cm

def votingDecision(results_dataset):
    pred_sys = results_dataset['sys_prob_ben']
    pred_ntd = results_dataset['ntd_prob_ben']
    pred_perms = results_dataset['perms_prob_ben']
    
    sta = time.time()
    majority_voting = [v/3.0 for v in[sum(x) for x in zip(pred_sys, pred_ntd, pred_perms)]]
    end = time.time()
    
    
    mal_voting = []    
    for item in majority_voting:
        mal_voting.append(1 - item)
    
    final_pred = []
    for item in majority_voting:
        if item >= 0.5:
            final_pred.append(0)
        else:
            final_pred.append(1)
    
    results_dataset['voting_prob_ben'] = majority_voting
    results_dataset['voting_prob_mal'] = mal_voting
    results_dataset['final_pred'] = final_pred
    
    final_accuracy = accuracy_score(results_dataset['y_true'], final_pred)*100
    final_fScore = f1_score(results_dataset['y_true'], final_pred)
    final_cm = confusion_matrix(results_dataset['y_true'], final_pred)
    
    return results_dataset, final_accuracy, final_fScore, final_cm, (end-sta)

    #Plotting the ROC
def plotROC(df):

    plt.figure()
    plt.xlabel('False Positive Rate', fontsize=12, fontweight='bold')
    plt.ylabel('True Positive Rate', fontsize=12, fontweight='bold')

    y_test = df['y_true']
    
#    probs.append(df['sys_prob_ben'])
    probs = df['sys_prob_mal']
    fpr, tpr, thresholds = roc_curve(y_test, probs)
    roc_auc = roc_auc_score(y_test, probs)
    plt.plot(fpr, tpr, 'm-.', linewidth=1.5, label='System Calls Model ROC (AUC %0.3f)'%roc_auc)
    
    probs = df['ntd_prob_mal']
#    probs.append(df['ntd_prob_mal'])
    fpr, tpr, thresholds = roc_curve(y_test, probs)
    roc_auc = roc_auc_score(y_test, probs)
    plt.plot(fpr, tpr, 'g-', linewidth=1.5, label='Network Traffic Model ROC (AUC %0.3f)'%roc_auc)
    
    probs = df['perms_prob_mal']
    fpr, tpr, thresholds = roc_curve(y_test, probs)
    roc_auc = roc_auc_score(y_test, probs)
    plt.plot(fpr, tpr, 'r--', linewidth=1.5, label='Permissions Model ROC (AUC %0.3f)'%roc_auc)

#    probs.append(df['voting_prob_ben'])
    probs = df['voting_prob_mal']
    fpr, tpr, thresholds = roc_curve(y_test, probs)
    roc_auc = roc_auc_score(y_test, probs)
    plt.plot(fpr, tpr, 'b:', linewidth=1.5, label='Voting Model ROC (AUC %0.3f)'%roc_auc)


    plt.legend(loc='lower right', fontsize=12)
    plt.xticks(fontsize=12)
    plt.yticks(fontsize=12)
#    plt.show()
    plt.savefig("CombinedROC.png", format='png', dpi=1000)

    
def plotCM(key, cm, path):
    plt.figure()     
    cmd_obj = ConfusionMatrixDisplay(cm, display_labels = ["Benign", "Malicious"])
    cmd_obj.plot(cmap = plt.cm.Purples)
    cmd_obj.ax_.set(title=key+" Confusion Matrix", xlabel = "Predicted Labels", ylabel = "Actual Labels")
    plt.savefig(path+key+'_cm.png', format='png', dpi=1000)  


#def plotProbHM(df):    
#    correlation = df[['sys_prob_ben','ntd_prob_ben','perms_prob_ben','voting_prob_ben']]
#    correlation = correlation.transpose()
##    max_val = max(correlation.max())
##    min_val = min(correlation.min())  figsize=(10,100)  
#    fig = plt.figure(figsize=(20,10))
#    ax = fig.add_subplot()
#    cax = ax.matshow(correlation, vmin=0, vmax=1, cmap=plt.cm.Blues, aspect='auto' )
#    fig.colorbar(cax, orientation='horizontal')
#    y_ticks_labels = ['SC_probs','NTD_probs','PERMS_probs','Voting_probs']
#    y_ticks = np.arange(0,4,1)
#    x_ticks = np.arange(0,len(correlation.columns),10)
#    ax.set_yticks(y_ticks)
#    ax.set_yticklabels(y_ticks_labels, fontsize = 16)     
#    ax.set_xticks(x_ticks)
##    ax.set_xticklabels(x_ticks)
##    plt.show()
#    plt.savefig('Final_Heatmap.png', format='png', dpi = 1000)

def plotProbHM(df):
    plt.figure(figsize=(20,10))
    correlation = df[['sys_prob_ben','ntd_prob_ben','perms_prob_ben','voting_prob_ben']]
    correlation = correlation.transpose()
#    cmap = sns.diverging_palette(220, 14, sep =20, as_cmap = True)
    sns.set(font_scale=2)
    hmap = sns.heatmap(correlation, cmap = plt.cm.Blues, cbar_kws={'orientation': "horizontal"}, xticklabels=False, linewidths=1)
    hmap.figure.axes[-1].tick_params(labelsize = 20)
    hmap.set(xlabel = None)
#    hmap.set_yticks(range(len(correlation)+1),['SC_probs','NTD_probs','PERMS_probs','Voting_probs'])
    plt.yticks(range(len(correlation.index)+1), ['SC probs','NTD probs','PERMS probs','Voting probs'])
    plt.savefig('Final_Heatmap.png', format='png', dpi = 1000)
    
if __name__ == '__main__':
    
    directory_path = str(os.getcwd())
    
    
    sys_dataset = prepareSystemCalls(directory_path)
    ntd_dataset = prepareNTD(directory_path)
    perms_dataset = preparePerms(directory_path)
    
    
    sys_index = list(sys_dataset.index)
    ntd_index = list(ntd_dataset.index)
    perms_index = list(perms_dataset.index)
    
    temp = list(set(sys_index)&set(ntd_index)&set(perms_index))
    
    sys_dataset = sys_dataset.loc[temp]
    ntd_dataset = ntd_dataset.loc[temp]
    perms_dataset = perms_dataset.loc[temp]
    

    sysClf, ntdClf, permsClf = loadPkls(directory_path)

    sys_results, sys_cm = testing("sys",sys_dataset, sysClf) 
    ntd_results, ntd_cm = testing("ntd",ntd_dataset, ntdClf) 
    perms_results, perms_cm = testing("perms",perms_dataset, permsClf) 

    ntd_results = ntd_results.drop(['y_true'], axis = 1)    
    perms_results = perms_results.drop(['y_true'], axis = 1)    

    dataset = pd.merge(pd.merge(sys_results, ntd_results, left_index = True, right_index = True), perms_results, left_index = True, right_index = True)
    
    final_dataset, final_accuracy, final_fScore, final_cm, tt = votingDecision(dataset)
    
    print("Voting Classifier Accuracy: "+str(final_accuracy))
    print("Voting Classifier F1-Score: "+str(final_fScore))
    print("Voting Classifier CM: "+str(final_cm))
    print("Voting Classifier Detection Time: "+str(tt))

    #ROC
    plotROC(final_dataset)
        
    #Confusion Matrix
    plotCM("System Calls", sys_cm, directory_path+"\\test\\syscalls_modified\\")
    plotCM("Network Traffic", ntd_cm, directory_path+"\\test\\pcaps\\")
    plotCM("Permissions", perms_cm, directory_path+"\\test\\PermsCsv\\")
    plotCM("Average Voting", final_cm, directory_path+"\\test\\")
    final_dataset = pd.read_csv(directory_path+"\\FinalPredictionResults.csv") 
    plotProbHM(final_dataset)
 

    final_dataset.to_csv(directory_path+"\\FinalPredictionResults.csv")        

   
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
