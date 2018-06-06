## Synopsis

This project tracks the development of NS-2 (USC/ISI's Network Simulator) changes to the MAODV (Multicast Ad Hoc On Demand Distance Vector (AODV)) protocol to support QoS-efficient routing of multicast packets in a Core-Based Multicast Tree.

## Code Example

Only the changes to MAODV are added. The rest of the simulation engine can be downloaded from NS-2 or NS-3's website. Since a lot has changed in NS-3's development, there is a need for significant changes.

## Motivation

This project was developed during the 1999-2002 timeframe when mobile-ad hoc networks (MANET) were a hot topic and an alternative to True Mobile Computing using WiFi's adhoc network settings.

## Installation

Please follow the steps listed below to checkout maodv extensions:
1. clone the git repo cbt-mcast-qos.git using the following command: git clone https://github.com/ag8775/cbt-mcast-qos.git
2. Launch your favorite merge tool to merge the components in your just cloned workspace
3. Identify the function you wish to change under rbmwsimulator

## API Reference

Depending on the size of the project, if it is small and simple enough the reference docs can be added to the README. For medium size to larger projects it is important to at least provide a link to where the API reference docs live.

## Tests

Describe and show how to run the tests with code examples.

## Contributors

Please checkout research papers on "An Efficient Core Migration Protocol for Providing QoS in Wireless Mobile Ad hoc Networks (MANETs)" at Google Scholar: https://scholar.google.com/citations?user=vMfpdekAAAAJ&hl=en

## License

Free to reuse and disribute under the MIT license.