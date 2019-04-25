# Radix Card Apple PoC

Contains example project for the Radix Card Applet.

# Build

## Install then NetBeans 8.2 IDE with Java Card support

On a **Windows Computer** install the [NetBeans IDE 8.2](https://netbeans.org/downloads/8.2/)

*  Download the **All** version of NetBean IDE which includes **Java Card™ 3 Connected**
*  The NetBeans IDE depends on Java SE. We recommend that you install [Java SE 8](https://www.oracle.com/technetwork/java/javase/downloads/index.html).
*  Change install path of the NetBeans IDE to `C:\NetBeans_8.2` or any other **path which does not contains spaces**.

## Configure the Java Card Platform in the NetBeans 8.2 IDE

The you open this project in the NetBeans 8.2 IDE you will be asked to configure the javacard platform.

1.  Select **Manage Platforms** then **Add Platform ...**
1.  Pick **Java Card Platform**
1.  Navigate to `C:\NetBeans_8.2\javacard\JCDK3.0.2_ConnectedEdition`
    *  If you installed NetBeans to to a path with spaces (e.g. `C:\Program Files\...`) you will be in trouble here.
1.  Press **Next**, **Finish**, **OK**, **Close** to confirm and get out of the menues.


