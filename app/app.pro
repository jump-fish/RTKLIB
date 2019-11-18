TEMPLATE = subdirs

# 2019-11-18 @tt, only strsvr_qt application is needed.
#SUBDIRS= rtknavi_qt \
#	 rtkget_qt \
#         rtkplot_qt \
#         rtkpost_qt \
#         rtklaunch_qt \
#         srctblbrows_qt \
#         strsvr_qt \
#         rtkconv_qt
SUBDIRS= strsvr_qt

app.depends = src
