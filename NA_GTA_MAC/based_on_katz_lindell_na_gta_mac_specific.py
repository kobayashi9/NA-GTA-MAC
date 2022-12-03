import os
import math
import numpy as np
import hmac
import hashlib
import sys

p  = 32 #セキュリティパラメータ(int型)
d = 1 #検知できる陽性の数

path1 = "./test/100_1.txt" #改ざん前のメッセージファイル
path2 = "./test/100_2.txt" #改ざん後のメッセージファイル

#ファイル読み込み
with open(path1, "r") as f:
	msg_list = f.readlines()
	for i in range(len(msg_list)):
		msg_list[i] = msg_list[i].replace("\n","")

with open(path2, "r") as f:
	vfy_msg_list = f.readlines()
	for i in range(len(vfy_msg_list)):
		vfy_msg_list[i] = vfy_msg_list[i].replace("\n","") 
"""
id,メッセージのリスト作成
==========================
	id_num : idの総数(int型)
	msg_list : メッセージのリスト(bytes型)
==========================
"""
def make_im_tuples(id_num, msg_list):
	msg_list = str2bytes(msg_list)#メッセージの集合をstr型→bytes型にキャスト
	im_tuples_list = []
	for i in range(id_num):
		im_tuples_list.append([i, msg_list[i]])
	return im_tuples_list
"""
id,メッセージ,tagのリスト作成
==========================
	im_tuples_list : id,メッセージのリスト
	msg_list : メッセージのリスト(中身bytes型)
	imt_tuples_list : id,メッセージ,tagのリスト
==========================
"""
def make_imt_tuples(im_tuples_list, tags_list):
	imt_tuples_list = []
	for i in range(len(im_tuples_list)):
		imt_tuples_list.append([im_tuples_list[i][0],im_tuples_list[i][1], tags_list[i]])
	return imt_tuples_list

"""
str型→byte型にキャスト
==========================
	msg_list : メッセージのリスト(str型)
	msg_byte_list : メッセージのリスト(bytes型)
==========================
"""
def str2bytes(msg_list):
	msg_byte_list = []
	for i in msg_list:
		msg_byte_list.append(i.encode('utf-8'))
	return msg_byte_list

"""
秘密鍵の作成
==========================
	p : セキュリティパラメータ(int型)
	id_num : idの総数(int型)
	sc_keys_list : 秘密鍵のリスト(bytes型)
==========================
"""
def make_sckeys(p, id_num):
	sc_keys_list = []
	for i in range(id_num):
		sc_keys_list.append(os.urandom(p))
	return sc_keys_list
"""
タグの作成
==========================
	sc_keys_list : 秘密鍵のリスト(bytes型)
	im_tuples_list : id, メッセージのリスト
	tags_list : タグのリスト(中身str型)
==========================
"""
def make_tags(sc_keys_list, im_tuples_list):
	tags_list = []
	for i in range(len(im_tuples_list)):
		tags_list.append(hmac.new(sc_keys_list[i], im_tuples_list[i][1], hashlib.sha256).hexdigest())
	return tags_list

"""
テストグループの作成
==========================
	id_num : メッセージの総数
	gt_label_list : グループテストラベルのリスト
==========================
"""
def make_testgroups(id_num):
	count = 0
	gx_list = make_primelist(id_num)
	gt_label_list = [[] for _ in range(sum(gx_list))]
	for i in range(len(gx_list)):
		for j in range(id_num):
			gt_label_list[count+j%gx_list[i]].append(j)
		count += gx_list[i]
	return gt_label_list
"""
メッセージの総数に対してのNon-adaptive group-testingをするためのもの
==========================
	id_num : メッセージの総数
	gx_list : リストでありリストの総和がu × nの行列のuになる。
	※一つの要素が√n以上であり、それがd+1個で全ての要素が互いに素である。
	なおかつ、そのリストの総和が生成することのできる総和で最小でなければならない。
==========================
"""
def make_primelist(id_num):
	gx_list = []
	base = math.ceil(np.sqrt(id_num))
	i = 0
	while i < d+1:
		if i == 0:
			gx_list.append(base)
			i += 1
		else:
			base += 1
			for j in range(len(gx_list)):
				if math.gcd(base, gx_list[j]) != 1:
					break
				elif j == len(gx_list)-1: #リストの最後の要素までたどり着いたら(すべての要素において互いに素のとき)
					gx_list.append(base)
					i += 1	
				else:
					continue
	return gx_list
"""
Group-Testing tagの作成
==========================
	imt_tuples_ : id,メッセージ,tagのリスト
	Tu_list : グループテストタグのリスト(bytes型?)
==========================
"""
def make_gtatag(imt_tuples_list):
	id_num = len(imt_tuples_list)
	gt_label_list = make_testgroups(id_num)
	len_matrix = len(gt_label_list)
	Tu_list = []
	for i in range(len_matrix):
		id_list = []
		for j in range(len(gt_label_list[i])):
			if j == 0:
				Tu_list.append(int(imt_tuples_list[gt_label_list[i][j]][2], 16))
			else:
				Tu_list[i] ^= int(imt_tuples_list[gt_label_list[i][j]][2], 16)
	return Tu_list, gt_label_list
"""
グループテストタグ検証(検証部分)
==========================
	vfy_im_tuples_list :  id, メッセージのリスト
	Tu_list : グループテストタグのリスト(bytes型?)
	vfy_Tu_list : 検証者が作成するグループテストタグのリスト(bytes型)
	gt_label_list : グループテストラベルのリスト
	Js_list : 最終的に改ざんされたid,メッセージが格納されるリスト
==========================
"""
def remove_id(vfy_im_tuples_list, Tu_list, vfy_Tu_list, gt_label_list):
	Js_list = dict(vfy_im_tuples_list)
	gtt_num = len(Tu_list)
	sample_num = len(vfy_im_tuples_list)
	for i in range(gtt_num):
		if(Tu_list[i] == vfy_Tu_list[i]): #タグが一致しているとき
			for j in range(len(gt_label_list[i])):
				if(gt_label_list[i][j] in Js_list):
					Js_list.pop(gt_label_list[i][j])
		else:
			continue
	return  Js_list
"""
グループテストタグ検証(検証全体)
==========================
	sc_keys_list : 秘密鍵のリスト(中身bytes型)
	im_tuples_list : id,メッセージのリスト
	Tu_list : グループテストタグのリスト(bytes型?)
	vfy_tags_list : 検証用のタグのリスト(中身byte型)
	vfy_imt_tuples_list : 検証用のid,メッセージ,tagのリスト
	vfy_Tu_list : 検証者が作成するグループテストタグのリスト(bytes型?)
	gt_label_list : グループテストラベルのリスト
	Js_list : 最終的に改ざんされたid,メッセージが格納されるリスト
==========================
"""
def verify_gtatag(sc_keys_list, vfy_im_tuples_list, Tu_list):
	vfy_tags_list = make_tags(sc_keys_list, vfy_im_tuples_list)
	vfy_imt_tuples_list = make_imt_tuples(vfy_im_tuples_list, vfy_tags_list)
	vfy_Tu_, X = make_gtatag(vfy_imt_tuples_list)
	Js_ = remove_id(vfy_im_tuples_list, Tu_list, vfy_Tu_, X) #グループテストの検証をしている部分(Jsの中身が改ざんされたメッセージ)
	return Js_

def main():
	id_num =  len(msg_list) #idの総数
	im_tuples_list = make_im_tuples(id_num, msg_list) #id,msgの組のリスト生成
	sc_keys_list = make_sckeys(p, id_num) #秘密鍵のリスト生成
	
	tags_list = make_tags(sc_keys_list, im_tuples_list) #タグのリスト生成
	imt_tuples_list = make_imt_tuples(im_tuples_list, tags_list) #id,メッセージ,tagのリスト生成
	Tu_list, ids_list = make_gtatag(imt_tuples_list) # グループテスト用タグ生成

	#検証
	vfy_im_tuples_list = make_im_tuples(id_num, vfy_msg_list) #id,msgの組のリスト生成
	Js_list = verify_gtatag(sc_keys_list, vfy_im_tuples_list, Tu_list)
	print(Js_list)

	
if __name__ == '__main__':
	main()