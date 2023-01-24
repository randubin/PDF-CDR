from sewar.full_ref import uqi
from sewar.full_ref import mse
from sewar.full_ref import rmse
from sewar.full_ref import psnr
from sewar.full_ref import rmse_sw
from sewar.full_ref import ssim
from sewar.full_ref import ergas
from sewar.full_ref import scc
from sewar.full_ref import rase
from sewar.full_ref import sam
from sewar.full_ref import msssim
from sewar.full_ref import vifp
from sewar.full_ref import psnrb
from PIL import Image
import time
import pandas as pd
import os
import numpy as np


def read_image(path):
    return np.asarray(Image.open(path).convert('YCbCr'))


def save_csv(res, path):
    pd.DataFrame([res]).to_csv(path, sep=',')


output_base = "/Users/dani/Downloads/images/after/"
output_base2 = "/Users/dani/Downloads/images/before/"
quality_folder = "/Users/dani/git/PDF-CDR/dataset/"
comp_res = []

# for path in path_list:
for root, subdirs, files in os.walk(output_base):
    for filename in files:

        try:
            res = {}
            tic = time.perf_counter()
            file_path = os.path.join(root, filename)
            file_path2 = os.path.join(output_base2, filename)
            img1 = read_image(file_path)
            img2 = read_image(file_path2)
            print('start working on ', filename)
            #res['uqi'] = uqi(img1, img2)
            res['mse'] = mse(img1, img2)
            #res['rmse'] = rmse(img1, img2)
            res['psnr'] = psnr(img1, img2)
            # res['rmse_sw'] = rmse_sw(img1,img2)
            ssim_res = ssim(img1, img2)
            res['ssim_ssims'] = ssim_res[0]
            res['ssim_css'] = ssim_res[1]
            #res['ergas'] = ergas(img1, img2)
            #res['scc'] = scc(img1, img2)
            #res['rase'] = rase(img1, img2)
            #res['sam'] = sam(img1, img2)
            # res['msssim'] = msssim(img1,img2)[0]
            # res['vifp'] = vifp(img1,img2)
            res['psnrb'] = psnrb(img1, img2)
            comp_res.append(res)
            save_csv(res, quality_folder + filename + ".csv")

            print('finished: ', filename)
            toc = time.perf_counter()
            print(f"Analysis done in {toc - tic:0.4f} seconds")
        except:
            print("error: ", file_path, file_path2)
            print(res)
pd.DataFrame(comp_res).to_csv('image_quality_comp_final.csv',sep=",")