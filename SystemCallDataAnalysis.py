import os
import numpy as np
import matplotlib.pyplot as plt
import statsmodels.api as sm
import seaborn as sns
from sklearn.feature_extraction.text import CountVectorizer


'''
x = [
        '23 53 213 23 52 ... 234', // a trace
        '1 70 23 43 23 53 ... 232', // a trace
        ...
    ]
- Firstly, you have to load all the attack data and the benign data into the memory
put them into two lists, list_attack and list_benign
- the form of the list is same as x, process them with compute_the_trace_length to get two new lists
list_len_attack and list_len_benign
list_len_attack = [
                    3240,
                    1234,
                    7928,
                    ...
                  ]
'''


dir_path = str(os.getcwd()) + '\\syscalls_modified\\'

malicious_master_path = dir_path + '\\malicious\\'
benign_master_path =  dir_path + '\\benign\\'




def get_file_dir(root_path):
    # input: a string (master path)
    # return: a list (all the files' name under that path)

    file_list = os.listdir(root_path)
    file_list.sort()
    all_file = []

    for file_name in file_list:
        sub_path = os.path.join(root_path, file_name)
        all_file.append(sub_path)
    return all_file

# get_file_list function
def get_file_list(root_path):
    # input: a string
    # output: a list (file list)

    file_list = os.listdir(root_path)
    file_list.sort()
    all_file = []

    for file_name in file_list:
        all_file.append(file_name)
    return all_file

def get_x_matrix(path):
    Benign_log_dir = path
    Benign_file_dirs = get_file_dir(Benign_log_dir)
    
    x_Benign = []
    
    index = 0
    
    for trace in Benign_file_dirs:
        print(Benign_file_dirs[index],"is handling.")
        with open(trace, 'r') as f:
            x_Benign.append(f.read())
        index += 1
    return x_Benign
    

def compute_the_trace_length(x):
    # input: a list (contains traces data)
    # output: a list (contains length of each trace)
    len_list_x = []
    for trace in x:
        trace = trace.split()
        trace_length = len(trace)
        len_list_x.append(trace_length)
    return len_list_x



# don't forget to modify the labels
def plot_trace_cdf_attack_and_normal(len_list_x_1, len_list_x_2):
    # input: two lists (one contains all the lengths of attack data and one contains all the lengths of normal data)
    # output: a plot contains two cdf curves
    # turn two lists into ndarrays of numpy and sort them
    len_array_x_1 = np.sort(np.array(len_list_x_1))
    len_array_x_2 = np.sort(np.array(len_list_x_2))
    # plot the cdf of attack data
    ecdf1 = sm.distributions.ECDF(len_array_x_1)
    x1 = np.linspace(min(len_array_x_1), max(len_array_x_1), 2000)
    y1 = ecdf1(x1)
    

    # plot the cdf of normal data

    ecdf2 = sm.distributions.ECDF(len_array_x_2)
    x2 = np.linspace(min(len_array_x_2), max(len_array_x_2), 2000)
    y2 = ecdf2(x2)


    # plot the values at 100/200/300/400/500 trace length
    point_array = [500, 1000, 2000, 3000, 4000, 5000]
    point_array = np.array(point_array)
    value_from_x1 = ecdf1(point_array)
    value_from_x2 = ecdf2(point_array)
    
    # print the values 100/200/300/400/500 trace length
    #print(value_from_x1)
    #print(value_from_x2)

    # setting title, legend, xlabel and ylabel
    #plt.title("CDF Curves of Attack data and Normal data")
        # create a new figure
    plt.figure(figsize=(12, 9))
    plt.plot(x1, y1, label="Malicious data")
    plt.plot(x2, y2, label="Benign data")
    plt.legend(loc= 'lower right', fontsize=16)
    plt.xlabel('System Call Trace Length', fontsize=16)
    plt.ylabel('Cumulative Distribution', fontsize=16)
    plt.xticks(np.arange(0,max(len_list_x_2),10000),fontsize=14, rotation=-45)
    plt.yticks(fontsize=14)
    plt.grid(linestyle='-.')
    plt.scatter(point_array, value_from_x2, c="#ED7D31")
    plt.scatter(point_array, value_from_x1, c="blue")
    #plt.show()

    # save the figure
    plt.savefig(dir_path+"Mal_Benign_cdf_curves.png")
  
def get_distribution(len_of_record):
    limits = [500, 1000, 2000, 3000, 4000, 5000]
    size = len(len_of_record)
    amount = [0 for _ in range(len(limits) + 1)]
    for record in len_of_record:
        pos = -2
        for i in range(len(limits) - 1, -1, -1):
            if record > limits[i]:
                pos = i + 1
                break
        if pos == -2:
            amount[0] = amount[0] + 1
            continue
        amount[pos] = amount[pos] + 1
        
    
    for i in range(1, len(amount), 1):
        amount[i] = amount[i] + amount[i - 1]
    
    percent = [round(x / size, 2) for x in amount]
    
    return percent
        
    

def plot_distribution_figure(len_list_x_Benign, len_list_x_Mal):
    plt.figure(figsize=(13.98, 8.92))
    sns.distplot(len_list_x_Benign,  label = "Normal")
    sns.distplot(len_list_x_Mal, axlabel="Length of Records", label = "Attack")
    plt.legend()
    plt.title("Distributions of Attack data and Normal data")
    plt.xticks(np.arange(0,max(len_list_x_Benign),5000))
    plt.grid(axis='y',linestyle='-.')
    plt.show()
    plt.savefig(dir_path + "CDF.png")
    

def ngram_processing(x, ngram):
    # input: a list (trace list), an int (n-gram, like 2/3/4/5)
    # output: an array (2d, m*n), a list (feature name list)
    vectorizer = CountVectorizer(min_df=1, ngram_range=(ngram, ngram))  # apply n-gram model
    x = vectorizer.fit_transform(x)
    feature_name = vectorizer.get_feature_names()
    x = x.toarray()
    return x, feature_name
'''
after ngram_processing
x_xxx is an m*n ndarray.
m: number of traces
n: number of features
e.g For attack data, the number of traces is 91. If we apply 2-gram model to these data,
we will get 292 features so that the shape of x is a 91*292 ndarray.
Now we try to use numpy to make further process.
'''
def count_top_20_patterns(x, feature_name):
    # input: two lists (trace list after cutting and pattern name list)
    # output: two lists (top 10 frequent patterns and their quantities)
    # get the sum by each column
    x_column_sum = np.sum(x, axis=0)

    # get the index of top 10 frequent n-gram patterns
    x_index_top20 = np.argpartition(x_column_sum, -10)[-10:]

    # create a dictionary to store key and value
    x_key = []
    x_value = []
    for index in x_index_top20:
        x_key.append(feature_name[index])
        x_value.append(x_column_sum[index])
    x_dict = dict(zip(x_key, x_value))

    # sort the dictionary, the result is a list with 10 tuples
    x_dict = sorted(x_dict.items(), key=lambda item: item[1], reverse=True)

    # use x_key to store the patterns and x_value to store the values
    x_key = []
    x_value = []
    for pattern_with_value in x_dict:
        x_key.append(pattern_with_value[0])
        x_value.append(pattern_with_value[1])
    print(x_key)
    print(x_value, '\n')
    return x_key, x_value


def plot_top_20_patterns(key_list, value_list, n_gram, attack_name):
    # input: two lists (store key and value)
    # output: a plot show the top 10 patterns
    x = range(len(value_list))
    print(n_gram)
    # create a new figure
    # 2-3gram figsize=(13.98, 8.92) 4-gram figsize=(17.5, 8.92) 5-gram figsize=(22, 8.92)
    if n_gram == 1 or n_gram == 2:
        print("1 or 2")
        plt.figure(figsize=(18, 9))
    elif n_gram == 3:
        print("3")
        plt.figure(figsize=(21, 14))
    elif n_gram == 4:
        print("4")
        plt.figure(figsize=(21, 14))
    rects_1 = plt.bar(x, height=value_list, width=0.3, label=attack_name)

    plt.ylim(0, value_list[0]*1.1)  # range for y-axis
    plt.ylabel("Quantity", fontsize=15)
    
    if n_gram == 1 or n_gram == 2:
        print("1 or 2")
        plt.xticks([index for index in x], key_list,fontsize=14)
    elif n_gram == 3:
        print("3")
        plt.xticks([index for index in x], key_list, rotation = -20,fontsize=14)
    elif n_gram == 4:
        print("4")
        plt.xticks([index for index in x], key_list, rotation = -25,fontsize=14)
    
    plt.xlabel("Patterns", fontsize=16)
    plt.yticks(fontsize=14)
    #plt.title(attack_name + "patterns in " + str(n_gram) + "-gram with")
    #plt.legend()

    for rect in rects_1:
        height = rect.get_height()
        plt.text(rect.get_x() + rect.get_width() / 2, height + 1, str(height), ha="center", va="bottom")
    plt.savefig(dir_path + str(n_gram) + "gram" + attack_name + ".png")
    #plt.show()
    
def get_top_20_comparison_patterns_data(x_Benign, x_Mal, ngram, topn):
    x, feature_name = ngram_processing(x_Benign, ngram)
    x_key_benign, x_value_benign  = get_all_common_patterns(x, feature_name)
    x_value_benign = [value / max(x_value_benign) for value in x_value_benign]
    
    x, feature_name = ngram_processing(x_Mal, ngram)
    x_key_mal, x_value_mal = get_all_common_patterns(x, feature_name)
    x_value_mal = [value / max(x_value_mal) for value in x_value_mal]
    
    common_comparsion = []
    
    for i in range(len(x_key_benign)):
        common_comparsion.append([x_key_benign[i], x_value_benign[i], 0])
        
    for i in range(len(x_key_mal)):
        pos = -1
        for j in range(len(common_comparsion)):
            if common_comparsion[j][0] == x_key_mal[i]:
                pos = j
        
        if pos == -1:
            common_comparsion.append([x_key_mal[i], 0, x_value_mal[i]])
        else:
            common_comparsion[pos][2] = x_value_mal[i]
            
    #print(common_comparsion)
    
    abs_common_comparsion = []
    
    for i in range(len(common_comparsion)):
        abs_common_comparsion.append([common_comparsion[i][0], abs(common_comparsion[i][1] - common_comparsion[i][2])])
        
    for i in range(len(common_comparsion)):
        pos = -1
        for j in range(len(abs_common_comparsion)):
            if abs_common_comparsion[j][0] == common_comparsion[i][0]:
                pos = j
        
        if pos == -1:
            print("Not Found")
        else:
            common_comparsion[i].append(abs_common_comparsion[pos][1])
            
            
    common_comparsion_sorted = sorted(common_comparsion, key = lambda x : x[-1], reverse = True)
    np.savetxt(dir_path + str(ngram) + 'gram_common_comparsion_sorted.csv',common_comparsion_sorted,delimiter=',',fmt='%s')
    
    
    comparsion_key = [common_comparsion_sorted[i][0] for i in range(topn)]
    comparsion_value1 = [round(common_comparsion_sorted[i][1],2) for i in range(topn)]
    comparsion_value2 = [round(common_comparsion_sorted[i][2],2) for i in range(topn)]
    
    return comparsion_key, comparsion_value1, comparsion_value2
    
    
#For plotting 
def plot_top_20_comparison_patterns(key_list, value_list, value_list2, n_gram):
    # input: two lists (store key and value)
    # output: a plot show the top 10 patterns
    x = list(range(len(value_list)))

    # create a new figure    
    if n_gram == 1 or 2:
        plt.figure(figsize=(10, 10))
    elif n_gram == 3:
        plt.figure(figsize=(10, 24))
    elif n_gram == 4:
        plt.figure(figsize=(10, 24))
    
    bar_width = 0.3
        
    rects_1 = plt.bar(x, value_list, bar_width, label= 'Benign Data')
    
    newx = [x1 + bar_width for x1 in x]
    
    
    rects_1 = plt.bar(newx, value_list2, bar_width, label= 'Malicious Data')
    

    #plt.ylim(0, value_list[0]*1.5)  # range for y-axis
    plt.ylim(0, 1)  # range for y-axis
    
    plt.ylabel("Ratio", fontsize=16)
    plt.yticks(fontsize=14)
    
    x_pos = range(len(key_list))
    
    if n_gram == 1 or n_gram == 2:
        print("1 or 2")
        plt.xticks([index for index in x_pos], key_list, rotation = -15,fontsize=14)
    elif n_gram == 3:
        print("3")
        plt.xticks([index for index in x_pos], key_list, rotation = -90,fontsize=14)
    elif n_gram == 4:
        print("4")
        plt.xticks([index for index in x_pos], key_list, rotation = -90,fontsize=14)
    
    plt.xlabel("Patterns", fontsize=16)
    #plt.title("comparison of Benign and Malicious patterns in " + str(n_gram) +
    
#    "-gram")
    plt.legend(fontsize = 16)

    #for rect in rects_1:
        #height = rect.get_height()
        #plt.text(rect.get_x() + rect.get_width() / 2, height + 1, str(height), ha="center", va="bottom")
    plt.savefig(dir_path + str(n_gram) + "_gram" + ".png")
    #plt.show()



def get_top20_common_patterns(x, feature_name):
    # input: two lists (trace list after cutting and pattern name list)
    # output: two lists (top 10 frequent patterns and their quantities)
    # get the sum by each column
    
    x[x > 1] = 1
    
    x_column_sum = np.sum(x, axis=0)

    # get the index of top 10 frequent n-gram patterns
    x_index_top20 = np.argpartition(x_column_sum, -20)[-20:]

    # create a dictionary to store key and value
    x_key = []
    x_value = []
    for index in x_index_top20:
        x_key.append(feature_name[index])
        x_value.append(x_column_sum[index])
    x_dict = dict(zip(x_key, x_value))

    # sort the dictionary, the result is a list with 10 tuples
    x_dict = sorted(x_dict.items(), key=lambda item: item[1], reverse=True)

    # use x_key to store the patterns and x_value to store the values
    x_key = []
    x_value = []
    for pattern_with_value in x_dict:
        x_key.append(pattern_with_value[0])
        x_value.append(pattern_with_value[1])
    print(x_key)
    print(x_value, '\n')
    return x_key, x_value


def get_all_common_patterns(x, feature_name):
    # input: two lists (trace list after cutting and pattern name list)
    # output: two lists (top 10 frequent patterns and their quantities)
    # get the sum by each column
    
    x[x > 1] = 1
    
    x_column_sum = np.sum(x, axis=0)

    # get the index of top 10 frequent n-gram patterns
    x_index_top20 = np.argpartition(x_column_sum, -len(feature_name))[-len(feature_name):]

    # create a dictionary to store key and value
    x_key = []
    x_value = []
    for index in x_index_top20:
        x_key.append(feature_name[index])
        x_value.append(x_column_sum[index])
    x_dict = dict(zip(x_key, x_value))

    # sort the dictionary, the result is a list with 10 tuples
    x_dict = sorted(x_dict.items(), key=lambda item: item[1], reverse=True)

    # use x_key to store the patterns and x_value to store the values
    x_key = []
    x_value = []
    for pattern_with_value in x_dict:
        x_key.append(pattern_with_value[0])
        x_value.append(pattern_with_value[1])
    print(x_key)
    print(x_value, '\n')
    return x_key, x_value


if __name__ == "__main__":
    

    
    print("Starting Loading Data")
    try:
        x_Benign = np.loadtxt(dir_path+'x_Benign.csv',delimiter=',',dtype=str)
        len_list_x_Benign = np.loadtxt(dir_path+'len_list_x_Benign.csv')
    except IOError:
        x_Benign = get_x_matrix(benign_master_path)
        len_list_x_Benign = compute_the_trace_length(x_Benign)
        np.savetxt(dir_path+'len_list_x_Benign.csv',len_list_x_Benign,delimiter=',')
        np.savetxt(dir_path+'x_Benign.csv',x_Benign,delimiter=',',fmt='%s')
    
        
    try:
        x_Mal = np.loadtxt(dir_path+'x_Mal.csv',delimiter=',',dtype=str)
        len_list_x_Mal = np.loadtxt(dir_path+'len_list_x_Mal.csv')
    except IOError:
        x_Mal = get_x_matrix(malicious_master_path)
        len_list_x_Mal = compute_the_trace_length(x_Mal)
        np.savetxt(dir_path+'len_list_x_Mal.csv',len_list_x_Mal,delimiter=',')
        np.savetxt(dir_path+'x_Mal.csv',x_Mal,delimiter=',',fmt='%s')
        
    print("Finished Loading Data")

    benign_dis = get_distribution(len_list_x_Benign)
#    np.savetxt('Output_data/benign_dis.csv',benign_dis,delimiter=',',fmt='%s')
    mal_dis = get_distribution(len_list_x_Mal)
#    np.savetxt('Output_data/mal_dis.csv',mal_dis,delimiter=',',fmt='%s')
    plot_trace_cdf_attack_and_normal(len_list_x_Mal, len_list_x_Benign)

    
    # plot 2-4 gram comparsion figures
    for i in range(2,5):
        comparsion_key, comparsion_value1, comparsion_value2 = get_top_20_comparison_patterns_data(x_Benign, x_Mal, i, 10)
        plot_top_20_comparison_patterns(comparsion_key, comparsion_value1, comparsion_value2, i)
  
 
    
    
    
    
'''
    for i in range(1,5):
        x, feature_name = ngram_processing(x_Benign, i)
        x_key, x_value = count_top_20_patterns(x, feature_name)
        data = [list(t) for t in zip(x_key, x_value)]
        np.savetxt('Output_data/' + str(i) + 'gram_top20_Benign.csv', data, delimiter=',',fmt='%s')
        plot_top_20_patterns(x_key, x_value, i, 'Benign Top 20 Seqences' )
        print("successfully saved")
        
# getting top 20 sequence of Mal data
    for i in range(1,5):
        x, feature_name = ngram_processing(x_Mal, i)
        x_key, x_value = count_top_20_patterns(x, feature_name)
        data = [list(t) for t in zip(x_key, x_value)]
        np.savetxt('Output_data/' + str(i) + 'gram_top20_Mal.csv', data, delimiter=',',fmt='%s')
        plot_top_20_patterns(x_key, x_value, i, 'Malicious Top 20 Seqences' )
        print("successfully saved")

# getting common seqences
    for i in range(1,5):
        x, feature_name = ngram_processing(x_Benign, i)
        x_key, x_value = get_top20_common_patterns(x, feature_name)
        data = [list(t) for t in zip(x_key, x_value)]
        np.savetxt('Output_data/' + str(i) + 'gram_top20_common_Benign.csv', data, delimiter=',',fmt='%s')
        plot_top_20_patterns(x_key, x_value, i, 'Benign Top common 20 Seqences' )
        print("successfully saved")
    
    for i in range(1,5):
        x, feature_name = ngram_processing(x_Mal, i)
        x_key, x_value = get_top20_common_patterns(x, feature_name)
        data = [list(t) for t in zip(x_key, x_value)]
        np.savetxt('Output_data/' + str(i) + 'gram_top20_common_Mal.csv', data, delimiter=',',fmt='%s')
        plot_top_20_patterns(x_key, x_value, i, 'Malicious Top common 20 Seqences')
        print("successfully saved")
    
'''
    
    
    
    
    