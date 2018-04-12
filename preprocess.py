#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Apr 11 11:12:25 2018

@author: bbaker
"""

import os
import shutil
import json
import pandas
from sklearn.feature_extraction import DictVectorizer

HOME = os.getcwd()
print("Working in %s" % HOME)
SRC_SAVE = 'SRC%s' % os.sep
CG_SAVE = 'CGD%s' % os.sep
LABELS = ['CWE-119', 'CWE-399']
CGD = 'CGD'
SRC = 'source_files'
FILEFORM = '%s_%s%s'
TXTFILE = 'txt.txt'
LABELFILE = 'label.txt'
DO_SRC = False
DO_CG = True

srcpath = os.path.join(HOME, SRC_SAVE)
cgpath = os.path.join(HOME, CG_SAVE)
srcpaths = {L: os.path.join(HOME, L, SRC) for L in LABELS}
cgdpaths = {L: os.path.join(HOME, L, CGD) for L in LABELS}


def json_to_dict(filename):
    """ Simplify json loading """
    with open(filename, "rb") as json_file:
        object = json.load(json_file)
    return(object)


def pad_string(string, pad_len):
    """
        Pad a string with whitespace.
        This solution is a modified version of the solution posted here:
            https://stackoverflow.com/questions/
                    5676646/how-can-i-fill-out-a-python-string-with-spaces
    """
    string = ('{0: <%d}' % pad_len).format(string)  # left padding
    string = ('{0: >%d}' % pad_len).format(string)  # right padding
    return string


def src2sym(c_text, symbol_dict=None,
            symbol_json_filename="C_SYMBOL_MAP.json"):
    """
        This function converts all C operators into unique tokens which allows
        them to be viewed as tokens by the parser.
    """
    if not symbol_dict or type(symbol_dict) is not dict:
        symbol_dict = json_to_dict(symbol_json_filename)

    """
    Replace the longest symbols first to avoid collision. Pad the replacement
    strings to prevent token collision.

    Using solution from
    https://stackoverflow.com/questions/11753809/sort-dictionary-by-key-length
    """
    for punc in sorted(symbol_dict, key=len, reverse=True):
        c_text = c_text.replace(punc, pad_string(symbol_dict[punc], 1))
    c_text = c_text.replace("\n", " \n ")  # Pad the beginning and end of lines
    c_text = pad_string(c_text, 1)  # Pad the beginning and end of file
    return c_text


def src2vector(c_text, vectorizer=None, symbol=True, **kwargs):
    if symbol:
        c_text = src2sym(c_text, **kwargs)
    if vectorizer is None:
        vectorizer = DictVectorizer()
    vector = vectorizer.fit_transform(c_text)
    return dict(vector=vector, vectorizer=vectorizer)


def cg2sym(src, c_vocab='./c_base_vocab.txt'):
    '''
        Convert names of variables and functions to place-holders
    '''
    with open(c_vocab, 'r') as file:
        vocab = file.read()
    vocab = vocab.split('\n')
    tokens = src.split(' ')
    func_counter = 0
    var_counter = 0
    str_counter = 0
    vard = {}
    func = {}
    strs = {}
    for i, token in enumerate(tokens):
        if token not in vocab:
            if token in vard.keys():
                tokens[i] = vard[token]
                continue
            elif token in func.keys():
                tokens[i] = func[token]
                continue
            elif token in strs.keys():
                tokens[i] = strs[token]
                continue
            try:
                float(token)
                continue
            except ValueError:
                if '"' in token or "'" in token:
                    tokens[i] = 'STR%d' % str_counter
                    strs[token] = 'STR%d' % str_counter
                    str_counter += 1
                elif i < len(tokens)-1 and tokens[i+1] == '@lpar@':
                    tokens[i] = 'FUNC%d' % func_counter
                    func[token] = 'FUNC%d' % func_counter
                    func_counter += 1
                else:
                    tokens[i] = 'VAR%d' % var_counter
                    vard[token] = 'VAR%d' % var_counter
                    var_counter += 1
    return ' '.join(tokens)


def parse_cg(filename):
    print(filename)
    with open(filename, 'r', encoding='utf-8') as file:
        data = file.read()
    data = data.replace('\n', '@@')
    instances = data.split('---------------------------------')
    data_list = []
    for instance in instances:
        lines = instance.split('@@')
        lines = [l for l in lines if len(l) > 0]
        if len(lines) == 0:
            continue
        meta, label, src = lines[0], lines[-1], ' '.join(lines[1:-1])
        print(meta)
        src = src2sym(src)
        src = cg2sym(src)
        index, filename, ctype, lineno = meta.split()[:4]
        filename = os.path.basename(filename)
        dict_instance = dict(index=index, filename=filename, ctype=ctype,
                             lineno=lineno, label=label, src=src)
        data_list.append(dict_instance)
    df = pandas.DataFrame(data_list)
    return df


if DO_SRC:
    if os.path.exists(srcpath):
        print("Resetting %s" % srcpath)
        shutil.rmtree(srcpath)
    print("Making %s" % srcpath)
    os.makedirs(srcpath)
if DO_CG:
    if os.path.exists(cgpath):
        print("Resetting %s" % cgpath)
        shutil.rmtree(cgpath)
    print("Making %s" % cgpath)
    os.makedirs(cgpath)

for loadpath in cgdpaths:
    if not os.path.exists(loadpath):
        raise Exception("CGD dir %s not found" % loadpath)
for loadpath in srcpaths:
    if not os.path.exists(loadpath):
        raise Exception("SRC dir %s not found" % loadpath)

for label in LABELS:
    newline = ''
    if DO_SRC:
        for root, directories, filenames in os.walk(srcpaths[label]):
            for filename in filenames:
                prefix, ext = os.path.splitext(filename)
                if '.c' in ext:
                    filepath = os.path.join(root, filename)
                    try:
                        with open(filepath, 'r') as file:
                            source = file.read()
                        source = source.replace('\n', '')
                        savefilename = FILEFORM % (label, prefix, ext)
                        savepath = srcpath + savefilename
                        with open(savepath, 'w') as file:
                            file.write(source)
                        with open(os.path.join(srcpath, TXTFILE), 'w') as file:
                            file.write(newline + savefilename)
                        with open(os.path.join(srcpath, LABELFILE), 'w') as file:
                            file.write(newline + '%d' % LABELS.index(label))
                        newline = '\n'
                        print(savefilename, label)
                    except UnicodeDecodeError:
                        print("Unicode Decode Error in file %s" % filepath)
                        continue
    newline = ''
    if DO_CG:
        for root, directories, filenames in os.walk(cgdpaths[label]):
            for filename in filenames:
                prefix, ext = os.path.splitext(filename)
                if '.txt' in ext:
                    filepath = os.path.join(root, filename)
                    df = parse_cg(filepath)
                    for index, instance in df.iterrows():
                        source = instance['src']
                        gb_label = instance['label']
                        savefilename = label + '_' + instance['filename']
                        savepath = cgpath + savefilename
                        with open(savepath, 'w') as file:
                            file.write(source)
                        with open(os.path.join(cgpath, TXTFILE), 'a') as file:
                            file.write(newline + savefilename)
                        with open(os.path.join(cgpath, LABELFILE), 'a') as file:
                            file.write(newline + '%d' % LABELS.index(label))
                        with open(os.path.join(cgpath, label + '_'
                                  + LABELFILE), 'a') as file:
                            file.write(newline + '%s' % gb_label)
                        with open(os.path.join(cgpath, label + '_'
                                  + TXTFILE), 'a') as file:
                            file.write(newline + '%s' % savefilename)
                        newline = '\n'
