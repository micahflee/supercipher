import os, inspect, platform
from PyQt4 import QtCore, QtGui
import common

class FileList(QtGui.QListWidget):
    files_dropped = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        super(FileList, self).__init__(parent)
        self.setAcceptDrops(True)
        self.setIconSize(QtCore.QSize(32, 32))

        # drag and drop label
        self.drop_label = QtGui.QLabel(QtCore.QString('Drag and drop\nfiles here'), parent=self)
        self.drop_label.setAlignment(QtCore.Qt.AlignCenter)
        self.drop_label.setStyleSheet('background: url({0}/drop_files.png) no-repeat center center; color: #999999;'.format(common.supercipher_gui_dir))
        self.drop_label.hide()

        self.filenames = []
        self.update()

    def update(self):
        # file list should have a background image if empty
        if len(self.filenames) == 0:
            self.drop_label.show()
        else:
            self.drop_label.hide()

    def resizeEvent(self, event):
        self.drop_label.setGeometry(0, 0, self.width(), self.height())

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls:
            event.accept()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls:
            event.setDropAction(QtCore.Qt.CopyAction)
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        if event.mimeData().hasUrls:
            event.setDropAction(QtCore.Qt.CopyAction)
            event.accept()
            for url in event.mimeData().urls():
                filename = str(url.toLocalFile())
                self.add_file(filename)
        else:
            event.ignore()
        self.files_dropped.emit()

    def add_file(self, filename):
        if filename not in self.filenames:
            self.filenames.append(filename)

            basename = os.path.basename(filename)
            fileinfo = QtCore.QFileInfo(filename)
            ip = QtGui.QFileIconProvider()
            icon = ip.icon(fileinfo)

            if os.path.isfile(filename):
                size = self.human_readable_filesize(fileinfo.size())
                item = QtGui.QListWidgetItem('{0} ({1})'.format(basename, size))
                item.setToolTip(QtCore.QString(size))
            else:
                item = QtGui.QListWidgetItem(basename)
            
            item.setIcon(icon)
            self.addItem(item)

    def human_readable_filesize(self, b):
        thresh = 1024.0
        if b < thresh:
            return '{0} B'.format(b)
        units = ['KiB','MiB','GiB','TiB','PiB','EiB','ZiB','YiB']
        u = 0
        b /= thresh
        while b >= thresh:
            b /= thresh
            u += 1
        return '{0} {1}'.format(round(b, 1), units[u])

class FileSelection(QtGui.QVBoxLayout):
    def __init__(self):
        super(FileSelection, self).__init__()

        # file list
        self.file_list = FileList()
        self.file_list.currentItemChanged.connect(self.update)
        self.file_list.files_dropped.connect(self.update)

        # buttons
        self.add_files_button = QtGui.QPushButton('Add Files')
        self.add_files_button.clicked.connect(self.add_files)
        self.add_dir_button = QtGui.QPushButton('Add Folder')
        self.add_dir_button.clicked.connect(self.add_dir)
        self.delete_button = QtGui.QPushButton('Delete')
        self.delete_button.clicked.connect(self.delete_file)
        button_layout = QtGui.QHBoxLayout()
        button_layout.addWidget(self.add_files_button)
        button_layout.addWidget(self.add_dir_button)
        button_layout.addWidget(self.delete_button)

        # add the widgets
        self.addWidget(self.file_list)
        self.addLayout(button_layout)

        self.update()

    def update(self):
        # delete button should be disabled if item isn't selected
        current_item = self.file_list.currentItem()
        if not current_item:
            self.delete_button.setEnabled(False)
        else:
            self.delete_button.setEnabled(True)

        # update the file list
        self.file_list.update()

    def add_files(self):
        filenames = QtGui.QFileDialog.getOpenFileNames(caption='Choose files', options=QtGui.QFileDialog.ReadOnly)
        if filenames:
            for filename in filenames:
                self.file_list.add_file(str(filename))
        self.update()

    def add_dir(self):
        filename = QtGui.QFileDialog.getExistingDirectory(caption='Choose folder', options=QtGui.QFileDialog.ReadOnly)
        if filename:
            self.file_list.add_file(str(filename))
        self.update()

    def delete_file(self):
        current_row = self.file_list.currentRow()
        self.file_list.filenames.pop(current_row)
        self.file_list.takeItem(current_row)
        self.update()

