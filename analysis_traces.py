import numpy as np
import matplotlib.pyplot as plt
import statsmodels.api as sm
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

    # create a new figure
    plt.figure(figsize=(13.98, 8.92))

    # plot the cdf of attack data
    ecdf1 = sm.distributions.ECDF(len_array_x_1)
    x1 = np.linspace(min(len_array_x_1), max(len_array_x_1), 2000)
    y1 = ecdf1(x1)
    plt.plot(x1, y1, label="Attack data")

    # plot the cdf of normal data
    ecdf2 = sm.distributions.ECDF(len_array_x_2)
    x2 = np.linspace(min(len_array_x_2), max(len_array_x_2), 2000)
    y2 = ecdf2(x2)
    plt.plot(x2, y2, label="Normal data")

    # plot the values at 100/200/300/400/500 trace length
    point_array = [100, 200, 300, 400, 500]
    point_array = np.array(point_array)
    value_from_x1 = ecdf1(point_array)
    value_from_x2 = ecdf2(point_array)
    plt.scatter(point_array, value_from_x1)
    plt.scatter(point_array, value_from_x2)

    # print the values 100/200/300/400/500 trace length
    print(value_from_x1)
    print(value_from_x2)

    # setting title, legend, xlabel and ylabel
    plt.title("CDF Curves of Attack data and Normal data")
    plt.legend()
    plt.xlabel('System Call Trace Length')
    plt.ylabel('Cumulative Distribution')
    plt.show()

    # save the figure
    # plt.savefig("Experiment_results/05-09-2019-cdf-curves/Attack_Normal_cdf_curves.png")


'''
x = [
        '23 53 213 23 52 ... 234', // a trace
        '1 70 23 43 23 53 ... 232', // a trace
        ...
    ]
'''
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

'''
def count_top_10_patterns(x, feature_name):
    # input: two lists (trace list after cutting and pattern name list)
    # output: two lists (top 10 frequent patterns and their quantities)
    # get the sum by each column
    x_column_sum = np.sum(x, axis=0)

    # get the index of top 10 frequent n-gram patterns
    x_index_top10 = np.argpartition(x_column_sum, -10)[-10:]

    # create a dictionary to store key and value
    x_key = []
    x_value = []
    for index in x_index_top10:
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
'''

def count_top_10_patterns(x, feature_name):
    # input: two lists (trace list after cutting and pattern name list)
    # output: two lists (top 10 frequent patterns and their quantities)
    # get the sum by each column
    x_column_sum = np.sum(x, axis=0)

    # get the index of top 10 frequent n-gram patterns
    x_index_top10 = np.argpartition(x_column_sum, -10)[-10:]


    
    
    # create a dictionary to store key and value
    x_key = []
    x_value = []
    for index in x_index_top10:
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




def plot_top_10_patterns(key_list, value_list, window_size, n_gram, attack_name):
    # input: two lists (store key and value)
    # output: a plot show the top 10 patterns
    x = range(len(value_list))

    # create a new figure
    # 2-3gram figsize=(13.98, 8.92) 4-gram figsize=(17.5, 8.92) 5-gram figsize=(22, 8.92)
    plt.figure(figsize=(13.98, 8.92))
    rects_1 = plt.bar(x, height=value_list, width=0.3, label=attack_name)

    plt.ylim(0, value_list[0]*1.1)  # range for y-axis
    plt.ylabel("Quantity")
    plt.xticks([index for index in x], key_list)
    plt.xlabel("Patterns")
    plt.title(attack_name + " Top 10 patterns in " + str(n_gram) + "-gram with " + str(window_size) + " window size")
    plt.legend()

    for rect in rects_1:
        height = rect.get_height()
        plt.text(rect.get_x() + rect.get_width() / 2, height + 1, str(height), ha="center", va="bottom")
    # plt.show()
    # plt.savefig("Experiment_results/05-06-2019-freq-plot/" + str(n_gram) + "gram" + "_win" + str(window_size) + "/"+ attack_name + "_" + str(n_gram) + "gram" + "_win" + str(window_size) + ".png")
    
    
    
    
    '''Added by Akshay'''
def plot_top_10_patterns_new(key_list, value_list, attack_name, path):
    # input: two lists (store key and value)
    # output: a plot show the top 10 patterns
    x = range(len(value_list))
    value_list2 = [round(i/1000, 2) for i in value_list]
    # create a new figure
    # 2-3gram figsize=(13.98, 8.92) 4-gram figsize=(17.5, 8.92) 5-gram figsize=(22, 8.92)
    plt.figure(figsize=(14, 9))
    
    if attack_name == 'Malware':
        rects_1 = plt.bar(x, height=value_list2, width=0.5, label=attack_name, color = "#ED7D31") #- For malware
    else:
        rects_1 = plt.bar(x, height=value_list2, width=0.5, label=attack_name)                      

    plt.ylim(0, (value_list2[0]*1.1))  # range for y-axis
    plt.ylabel("Quantity (in thousands)", fontsize=16)
    plt.xticks([index for index in x], key_list, fontsize=14, rotation=315)
    plt.yticks(fontsize = 14)
    plt.xlabel("Patterns", fontsize=16)
    #plt.title(attack_name + " Top 10 patterns in " + str(n_gram) + "-gram with " + str(window_size) + " window size")
    plt.legend(fontsize = 16)

    for rect in rects_1:
        height = rect.get_height()
        plt.text(rect.get_x() + rect.get_width() / 2, height + 0.1, str(height), ha="center", va="bottom")
    #plt.show()
    plt.savefig(path+attack_name+"_top_10.png", format='png', dpi = 1000)    