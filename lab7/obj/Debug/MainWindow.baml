   M S B A M L   `   `   `  ����?  ;lab7, Version=1.0.0.0, Culture=neutral, PublicKeyToken=nullclr-namespace:lab7lab7  5   	       lab7.MainWindow   5   	   R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5   	   R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   $localclr-namespace:lab7     5   	     � Title$  
MainWindow��5   	   $	��490��6   $	��822��6)   .��5
      �  � RowDefinitions 5   
   �� 5      $
��Auto �6   �� 5      $��* �6   �� 5      $
��Auto �6    � ColumnDefinitions 5   
   �� 5      $��3* �6   �� 5      $��2* �6   .+�5   
   �� $��0��6   $��20(�6!   $
��Bold"�6/   $��Center=�6A   $��10q�6^   $��2��6j   USПрограмма для шифрования и цифровых подписей5      �� 5   
   $��1��6   $��0��6"   $��10q�62   .+�5      �� $(��"Введите сообщение:��6   �� 5      -   5        $��MessageTextBox��5      $	��100��6,   $	��0,5q�69   " �� VerticalScrollBarVisibility$
 Auto=�6F    �� AcceptsReturn . 6i   5      �� 5"   
   $��2��6   $��0��6"   $��10q�62   .+�5#      �� $��Результат:��6   �� 5$      -   5        $��ResultTextBox��5$      $	��100��6+   $	��0,5q�68   $
 Auto=�6E    .  �� 
IsReadOnly . 6}   5%      �� 5(   
   $��1��6   $��1��6"    �� Orientation$ Vertical=�62   $��Center=�6I   $��10q�6f   .+�5)      �� -   5        $��EncryptButton��5)      $��Зашифровать��6*   $	��150��6@   $��5q�6L   6W   �� 5*      -   5        $��DecryptButton��5*      $��Дешифровать��6*   $	��150��6@   $��5q�6L   6W   �� 5+      -   5        $��
SignButton��5+      $%��Добавить подпись��6'   $	��150��6B   $��5q�6N   6Y   �� 5,      -   5        $��
SendButton��5,      $+��%Отправить сообщение��6'   $	��150��6E   $��5q�6Q   6\   5-      5.      5/      