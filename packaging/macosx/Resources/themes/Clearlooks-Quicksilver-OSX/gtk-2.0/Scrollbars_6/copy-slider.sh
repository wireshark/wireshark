#!/bin/bash
#
cp -f slider-vert.png slider-vert-prelight.png
cp -f slider-vert.png slider-horiz-prelight.png
cp -f slider-vert.png slider-horiz.png
convert -rotate 90 slider-horiz.png slider-horiz.png
convert -rotate 90 slider-horiz-prelight.png slider-horiz-prelight.png
