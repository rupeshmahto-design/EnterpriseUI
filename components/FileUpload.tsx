
import React from 'react';
import { ProjectDocument } from '../types';

interface FileUploadProps {
  onFilesAdded: (docs: ProjectDocument[]) => void;
}

const FileUpload: React.FC<FileUploadProps> = ({ onFilesAdded }) => {
  const formatSize = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files) return;

    const files = Array.from(e.target.files);
    const newDocs: ProjectDocument[] = await Promise.all(
      files.map(async (file: File) => {
        const content = await file.text();
        
        let category: any = 'Other';
        const name = file.name.toLowerCase();
        if (name.includes('req')) category = 'Requirement';
        else if (name.includes('design') || name.includes('arch')) category = 'Architecture';
        else if (name.includes('case')) category = 'Business Case';
        else if (name.includes('budget') || name.includes('cost')) category = 'Budget';
        else if (name.includes('plan') || name.includes('schedule')) category = 'Plan';
        else if (name.includes('risk')) category = 'Risk Register';
        else if (name.includes('status')) category = 'Status Report';

        return {
          id: Math.random().toString(36).substr(2, 9),
          name: file.name,
          type: file.type,
          size: formatSize(file.size),
          content: content,
          category: category
        };
      })
    );

    onFilesAdded(newDocs);
  };

  return (
    <div className="relative border-2 border-dashed border-blue-400 rounded-lg p-10 text-center bg-blue-50/20 hover:bg-blue-50/40 transition-all cursor-pointer group">
      <input
        type="file"
        multiple
        onChange={handleFileChange}
        className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
        id="file-input"
      />
      <div className="flex flex-col items-center justify-center">
        <i className="fa-regular fa-file-lines text-5xl text-slate-700 mb-4"></i>
        <p className="text-blue-600 font-medium">Drag and drop files here</p>
        <p className="text-xs text-slate-400 mt-1">Supported: PDF, DOCX, XLSX, TXT</p>
      </div>
    </div>
  );
};

export default FileUpload;
