import sys
import glob
import time
import numpy as np

from sklearn.preprocessing import MinMaxScaler, StandardScaler

from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import AdaBoostClassifier

from joblib import dump, load
import addrulessnort
my_path = '/home/minh/newmljoblibtest/src/inspectors/ml_classifiers/'

if len(sys.argv) != 2:
    print('Something went wrong.\nUsage: python3 /path/to/ml_classifiers.py <algorithm_code>')
    sys.exit(1)

if __name__ == '__main__':
    input_data = []
    input_file = open (my_path + 'tmp/timeouted_connections.txt', 'r')
    output_file = open (my_path + 'tmp/timeouted_connections_results.txt', 'w')
    joblibs_folder = 'newjoblibs/'

    clf_joblibs = {'ab':'clf_ab.joblib', 'dt':'clf_dt.joblib'}
    #clf = load(my_path + 'joblibs/' + clf_joblibs[sys.argv[1]])
    clf = load(my_path + joblibs_folder + clf_joblibs[sys.argv[1]])
    scaler = load(my_path + joblibs_folder + 'scaler.joblib')
    
    for line in input_file.readlines():
        features = line.strip().split(' ')
        feature_vector = [float(x) for x in features]
        
        input_data.append(feature_vector)
        
    np_input_data = np.array(input_data)
    np_input_data_adjusted = scaler.transform(np_input_data)
    
    start_time = time.time()
    predictions = clf.predict(np_input_data_adjusted)
    print('#{}'.format(time.time() - start_time))
    
    for prediction in predictions:
        output_file.write(str(prediction) + '\n')
        
    input_file.close()
    output_file.close()

    addrulessnort.add_rules()

