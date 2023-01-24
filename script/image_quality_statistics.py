import os,sys
import pandas as pd
import numpy as np

path = "/Users/dani/git/PDF-CDR/dataset/image_diff/"
# iterate through all file
res = []
for file in os.listdir(path):
    # Check whether file is in text format or not
    if file.endswith(".csv"):
        file_path = f"{path}/{file}"
        df = pd.read_csv(file_path)
        ans_dict = {'mse':df.mse.values[0],'psnr':df.psnr.values[0],'ssim_ssims':df.ssim_ssims.values[0]}
        res.append(ans_dict)
pd.DataFrame(res).to_csv("/Users/dani/git/PDF-CDR/dataset/"+"qoe_res.csv",sep=",")
df = pd.DataFrame(res)
print(df.describe())