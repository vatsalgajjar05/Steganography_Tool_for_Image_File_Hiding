# **🖼️ Steganography Tool for Image/File Hiding**

### **(Developed during Elevate Labs Internship)**

---

## **📌 Overview**

This project is a **Python-based Image Steganography Tool** developed as part of an internship at **Elevate Labs**.
The application allows users to securely **hide and extract secret text or files inside digital images** using the **Least Significant Bit (LSB)** steganography technique.

The tool features a **simple and intuitive Graphical User Interface (GUI)** built with **Tkinter** and supports common image formats such as **PNG** and **BMP**.

---

## **🎯 Objective**

The objective of this project is to demonstrate the **practical implementation of steganography** for secure data hiding, ensuring that sensitive information can be concealed within images **without noticeable visual changes**.

---

## **✨ Features**

* 🔐 Hide secret **text** inside images
* 📁 Hide **files** inside images (**ZIP format recommended**)
* 🔓 Extract hidden text or files from stego images
* 🖼️ Supports **PNG and BMP** image formats
* 🧮 Uses **LSB (Least Significant Bit)** steganography technique
* 🖥️ User-friendly **Tkinter-based GUI**
* 🔑 Optional **XOR-based encryption** for added security
* 📤 Securely save extracted files

---

## **🛠️ Tools & Technologies Used**

* **Python** – Core programming language
* **Tkinter** – GUI development
* **Pillow (PIL)** – Image processing
* **Stepic** – Steganography support
* **OS & Pathlib** – File handling

> **Note:** Tkinter is included with standard Python installations and does not require separate installation.

---

## **📂 Project Structure**

```
Steganography_Tool_for_Image_File_Hiding/
│
├── Steganography_Tool.py   # Main GUI application
├── requirements.txt        # Project dependencies
├── README.md               # Project documentation
└── Images                  # Sample images 
```

---

## **⚙️ Installation & Setup**

### **1️⃣ Clone the Repository**

```bash
git clone https://github.com/your-username/image-steganography-tool-elevate-labs.git
cd image-steganography-tool-elevate-labs
```

### **2️⃣ Install Dependencies**

```bash
pip install -r requirements.txt
```

### **3️⃣ Run the Application**

```bash
python Steganography_Tool.py
```

---

## **🚀 How to Use**

### **🔹 Embed Data into Image**

1. Launch the application.
2. Select **Text** or **File** mode.
3. Enter secret text or choose a file to hide.
4. Select a **cover image (PNG/BMP)**.
5. *(Optional)* Enter a password for encryption.
6. Click **Embed Data** and save the generated stego image.

### **🔹 Extract Hidden Data**

1. Launch the application.
2. Select the **stego image**.
3. Enter the password *(if encryption was used)*.
4. Click **Extract Data**.
5. View extracted text or save the extracted file.

---

## **🔐 Steganography Technique Used**

The project uses the **Least Significant Bit (LSB-3)** technique, where the least significant bits of image pixels are modified to store hidden data.
This approach ensures **minimal visual distortion** while securely embedding information.

---

## **🏫 Internship Acknowledgment**

This project was developed as part of an internship at **Elevate Labs**, focusing on practical applications of **cybersecurity, data hiding, and secure communication techniques**.

---



