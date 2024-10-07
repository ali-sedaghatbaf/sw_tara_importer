import openpyxl
from openpyxl.drawing.image import Image


workbook = openpyxl.load_workbook("CEVT TARA.xlsx")
print(workbook.sheetnames)
# Get the active worksheet (or specify the sheet by name)
sheet = workbook["4. Item Definition"]

# List to hold images found in the workbook
images_in_sheet = []

# Loop through all images in the workbook
for image in sheet._images:
    # image.anchor contains the cell reference where the image is anchored
    print(image.anchor)
