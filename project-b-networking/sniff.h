#ifndef SNIFF_H
#define SNIFF_H

int start_sniff(const char *dev_name);
int start_sniff_filtered(const char *dev_name, const char *filter);

#endif // SNIFF_H