export const getType = (data: any) => {
  const dataType = typeof data;
  if (dataType === 'object') {
    return 'Utf8Array';
  }
  return dataType;
};
